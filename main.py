#!/usr/bin/env python3
"""
praxiServer — minimal, optimized VLESS-over-HTTPUpgrade reverse proxy + panel.

Single-file, stdlib-only (uvloop optional). Designed to deploy free on Railway,
where the platform edge does NOT enforce SNI == Host, so a "bug SNI"
(sni != host) works natively for DPI bypass.

Transport: httpupgrade (Xray). Same HTTP/1.1 `Upgrade: websocket` handshake as
WebSocket, but after the 101 the stream is RAW bytes — no WebSocket framing, no
masking. Lighter and faster than WS for proxying.

State is in-memory (resets on restart). v1 is focused on the proxy working
perfectly; no per-user traffic quotas yet.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import socket
import secrets
import time
import uuid as uuidlib
from urllib.parse import quote, parse_qs, urlparse

# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------

PORT = int(os.environ.get("PORT", "8000"))
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")
# Path the httpupgrade proxy listens on. Clients must use the same in `path=`.
WS_PATH = os.environ.get("WS_PATH", "/hu")
SECRET_KEY = os.environ.get("SECRET_KEY") or hashlib.sha256(
    ("praxi-secret:" + ADMIN_PASSWORD).encode()).hexdigest()

# Stateless auth cookie value (survives restarts while password is unchanged).
AUTH_TOKEN = hmac.new(SECRET_KEY.encode(), b"praxi-auth-v1", hashlib.sha256).hexdigest()

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
READ_BUF = 65536

# ------------------------------------------------------------------------------
# In-memory state
# ------------------------------------------------------------------------------

# users: uuid_str -> {"name": str, "created": epoch}
USERS = {}
# fast lookup of raw 16-byte UUIDs for VLESS auth
UUID_BYTES = set()
# extra addresses (clean IPs / domains) used to build alternative configs
ADDRESSES = []
# editable settings
SETTINGS = {"sni": ""}   # sni = your bug host; empty -> falls back to Host


def _seed_default_user():
    """Create one user on first boot so there's something to test with."""
    uid = str(uuidlib.uuid4())
    USERS[uid] = {"name": "default", "created": int(time.time())}
    _rebuild_uuid_index()


def _rebuild_uuid_index():
    UUID_BYTES.clear()
    for u in USERS:
        try:
            UUID_BYTES.add(uuidlib.UUID(u).bytes)
        except ValueError:
            pass


# ------------------------------------------------------------------------------
# VLESS
# ------------------------------------------------------------------------------

async def read_vless_header(reader):
    """
    Parse a VLESS request header from the raw stream.

    Layout:
      1  version
      16 uuid
      1  addon length (M)
      M  addons (skipped)
      1  command (1=TCP, 2=UDP, 3=Mux)
      2  port (big-endian)
      1  address type (1=IPv4, 2=domain, 3=IPv6)
      .. address
      .. payload (left buffered in `reader`)
    Returns (version, uuid_bytes, command, dst_host, dst_port) or None.
    """
    version = (await reader.readexactly(1))[0]
    uid = await reader.readexactly(16)
    addon_len = (await reader.readexactly(1))[0]
    if addon_len:
        await reader.readexactly(addon_len)
    command = (await reader.readexactly(1))[0]
    port = int.from_bytes(await reader.readexactly(2), "big")
    atype = (await reader.readexactly(1))[0]
    if atype == 1:
        host = socket.inet_ntoa(await reader.readexactly(4))
    elif atype == 2:
        dlen = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(dlen)).decode("utf-8", "replace")
    elif atype == 3:
        host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
    else:
        return None
    return version, uid, command, host, port


# ------------------------------------------------------------------------------
# Proxy (httpupgrade)
# ------------------------------------------------------------------------------

def ws_accept(key):
    return base64.b64encode(
        hashlib.sha1((key + WS_GUID).encode()).digest()).decode()


async def handle_proxy(reader, writer, headers):
    """Complete the httpupgrade handshake, then relay VLESS TCP traffic."""
    # 101 handshake. We include Sec-WebSocket-Accept so strict edges (Railway,
    # nginx) open the tunnel; the httpupgrade client ignores the extra header.
    key = headers.get("sec-websocket-key", "")
    resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
    if key:
        resp += f"Sec-WebSocket-Accept: {ws_accept(key)}\r\n"
    resp += "\r\n"
    writer.write(resp.encode())
    await writer.drain()

    # Parse + authenticate VLESS.
    try:
        parsed = await read_vless_header(reader)
    except (asyncio.IncompleteReadError, ConnectionError):
        return _safe_close(writer)
    if not parsed:
        return _safe_close(writer)
    version, uid, command, dhost, dport = parsed
    if uid not in UUID_BYTES:
        return _safe_close(writer)
    if command != 1:                      # TCP only
        return _safe_close(writer)

    # Connect outbound.
    try:
        dst_reader, dst_writer = await asyncio.wait_for(
            asyncio.open_connection(dhost, dport), timeout=10)
    except (OSError, asyncio.TimeoutError):
        return _safe_close(writer)

    # VLESS response header: [version, 0].
    writer.write(bytes([version, 0]))
    try:
        await writer.drain()
    except ConnectionError:
        _safe_close(dst_writer)
        return _safe_close(writer)

    await _relay(reader, writer, dst_reader, dst_writer)


async def _relay(c_reader, c_writer, d_reader, d_writer):
    """Bidirectional raw relay; closes both sides when either end finishes."""
    async def pipe(r, w):
        try:
            while True:
                data = await r.read(READ_BUF)
                if not data:
                    break
                w.write(data)
                await w.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass

    t1 = asyncio.ensure_future(pipe(c_reader, d_writer))
    t2 = asyncio.ensure_future(pipe(d_reader, c_writer))
    try:
        await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in (t1, t2):
            t.cancel()
        _safe_close(c_writer)
        _safe_close(d_writer)


def _safe_close(writer):
    try:
        writer.close()
    except Exception:
        pass


# ------------------------------------------------------------------------------
# HTTP helpers (raw)
# ------------------------------------------------------------------------------

async def read_request(reader):
    """Read request line + headers. Returns (method, target, headers) or None."""
    try:
        raw = await reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
        return None
    lines = raw.split(b"\r\n")
    try:
        method, target, _ = lines[0].decode("latin-1").split(" ", 2)
    except ValueError:
        return None
    headers = {}
    for line in lines[1:]:
        if not line or b":" not in line:
            continue
        k, v = line.split(b":", 1)
        headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return method, target, headers


async def read_body(reader, headers):
    n = int(headers.get("content-length", "0") or "0")
    if n <= 0:
        return b""
    try:
        return await reader.readexactly(n)
    except (asyncio.IncompleteReadError, ConnectionError):
        return b""


async def send(writer, status, body, ctype="text/html; charset=utf-8", extra=None):
    if isinstance(body, str):
        body = body.encode("utf-8")
    head = [
        f"HTTP/1.1 {status}",
        f"Content-Type: {ctype}",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    if extra:
        head += extra
    writer.write(("\r\n".join(head) + "\r\n\r\n").encode() + body)
    try:
        await writer.drain()
    except ConnectionError:
        pass
    _safe_close(writer)


async def send_json(writer, obj, status="200 OK", extra=None):
    await send(writer, status, json.dumps(obj), "application/json", extra)


def is_authed(headers):
    return f"session={AUTH_TOKEN}" in headers.get("cookie", "")


# ------------------------------------------------------------------------------
# Config generation
# ------------------------------------------------------------------------------

def build_user_configs(uid, host):
    info = USERS.get(uid)
    if not info:
        return []
    sni = SETTINGS.get("sni") or host
    epath = quote(WS_PATH, safe="")
    addrs = [host] + [a for a in ADDRESSES if a]
    out = []
    for i, addr in enumerate(addrs, 1):
        link = (
            f"vless://{uid}@{addr}:443"
            f"?encryption=none&security=tls&sni={sni}&fp=chrome"
            f"&type=httpupgrade&host={host}&path={epath}&alpn=http%2F1.1"
            f"#{quote(info['name'])}-{i}"
        )
        out.append(link)
    return out


# ------------------------------------------------------------------------------
# Panel
# ------------------------------------------------------------------------------

LOGIN_HTML = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>praxi</title><style>
body{font-family:system-ui;background:#0b0e14;color:#e6e6e6;display:flex;
height:100vh;align-items:center;justify-content:center;margin:0}
.box{background:#151a23;padding:2rem;border-radius:12px;width:280px}
input,button{width:100%;padding:.7rem;margin:.4rem 0;border-radius:8px;
border:1px solid #2a3140;background:#0b0e14;color:#e6e6e6;box-sizing:border-box}
button{background:#3b82f6;border:0;cursor:pointer;font-weight:600}
h2{margin:0 0 1rem}</style></head><body>
<div class=box><h2>praxiServer</h2>
<input id=p type=password placeholder=Password>
<button onclick=login()>Login</button>
<div id=e style=color:#f87171;font-size:.85rem></div></div>
<script>
async function login(){
 const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({password:document.getElementById('p').value})});
 if(r.ok){location.href='/panel'}else{document.getElementById('e').textContent='Wrong password'}
}
document.getElementById('p').addEventListener('keydown',e=>{if(e.key==='Enter')login()});
</script></body></html>"""

PANEL_HTML = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>praxi panel</title><style>
body{font-family:system-ui;background:#0b0e14;color:#e6e6e6;margin:0;padding:1rem;max-width:900px;margin:auto}
h1{font-size:1.3rem}h3{margin-top:1.6rem}
.card{background:#151a23;padding:1rem;border-radius:12px;margin:.6rem 0}
input,button{padding:.55rem;border-radius:8px;border:1px solid #2a3140;background:#0b0e14;color:#e6e6e6}
button{background:#3b82f6;border:0;cursor:pointer;font-weight:600}
button.d{background:#ef4444}button.g{background:#22c55e}
table{width:100%;border-collapse:collapse;font-size:.9rem}
td,th{text-align:left;padding:.4rem;border-bottom:1px solid #222a37;word-break:break-all}
.row{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center}
small{color:#8b98ab}code{color:#93c5fd}
</style></head><body>
<div class=row style=justify-content:space-between>
 <h1>praxiServer</h1><button class=d onclick="fetch('/api/logout',{method:'POST'}).then(()=>location.href='/login')">Logout</button>
</div>

<div class=card><h3>Bug SNI</h3>
 <small>Domain your ISP lets through. Empty = use server host.</small>
 <div class=row style=margin-top:.5rem>
  <input id=sni placeholder="your.bug.host" style=flex:1>
  <button class=g onclick=saveSni()>Save</button>
 </div>
</div>

<div class=card><h3>Clean IPs / addresses</h3>
 <div class=row style=margin-bottom:.5rem>
  <input id=addr placeholder="104.21.x.x or domain" style=flex:1>
  <button class=g onclick=addAddr()>Add</button>
 </div>
 <div id=addrs></div>
</div>

<div class=card><h3>Users</h3>
 <div class=row style=margin-bottom:.5rem>
  <input id=uname placeholder="name" style=flex:1>
  <button class=g onclick=addUser()>+ Add user</button>
 </div>
 <table><thead><tr><th>Name</th><th>Sub link</th><th></th></tr></thead>
 <tbody id=users></tbody></table>
</div>

<script>
const j=(u,o)=>fetch(u,o).then(r=>r.json());
async function load(){
 const s=await j('/api/settings');document.getElementById('sni').value=s.sni||'';
 const a=await j('/api/addresses');
 document.getElementById('addrs').innerHTML=a.map((x,i)=>
  `<div class=row style=justify-content:space-between><code>${x}</code>
   <button class=d onclick=delAddr(${i})>x</button></div>`).join('')||'<small>none</small>';
 const u=await j('/api/links');
 document.getElementById('users').innerHTML=u.map(x=>
  `<tr><td>${x.name}</td>
   <td><code>${location.origin}/sub/${x.uuid}</code></td>
   <td><button onclick="navigator.clipboard.writeText(location.origin+'/sub/${x.uuid}')">copy</button>
   <button class=d onclick="delUser('${x.uuid}')">del</button></td></tr>`).join('');
}
async function saveSni(){await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({sni:document.getElementById('sni').value.trim()})});load()}
async function addAddr(){const v=document.getElementById('addr').value.trim();if(!v)return;
 await fetch('/api/addresses',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({addr:v})});document.getElementById('addr').value='';load()}
async function delAddr(i){await fetch('/api/addresses',{method:'DELETE',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({index:i})});load()}
async function addUser(){const v=document.getElementById('uname').value.trim()||'user';
 await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({name:v})});document.getElementById('uname').value='';load()}
async function delUser(u){await fetch('/api/links',{method:'DELETE',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({uuid:u})});load()}
load();
</script></body></html>"""

NGINX_HTML = """<!DOCTYPE html><html><head><title>Welcome to nginx!</title>
<style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif}</style>
</head><body><h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>
<p><em>Thank you for using nginx.</em></p></body></html>"""


async def handle_panel(reader, writer, method, target, headers):
    parsed = urlparse(target)
    path = parsed.path
    body = await read_body(reader, headers)

    def jbody():
        try:
            return json.loads(body or b"{}")
        except json.JSONDecodeError:
            return {}

    # public routes
    if path == "/health":
        return await send(writer, "200 OK", "ok", "text/plain")
    if path == "/login":
        return await send(writer, "200 OK", LOGIN_HTML)
    if path == "/api/login" and method == "POST":
        if jbody().get("password") == ADMIN_PASSWORD:
            cookie = f"session={AUTH_TOKEN}; HttpOnly; Path=/; SameSite=Strict; Max-Age=86400"
            return await send_json(writer, {"ok": True}, extra=[f"Set-Cookie: {cookie}"])
        return await send_json(writer, {"ok": False}, "401 Unauthorized")
    if path.startswith("/sub/"):
        uid = path[len("/sub/"):]
        host = headers.get("host", "").split(":")[0]
        links = build_user_configs(uid, host)
        data = base64.b64encode(("\n".join(links)).encode()).decode()
        return await send(writer, "200 OK", data, "text/plain; charset=utf-8")
    if path == "/":
        return await send(writer, "200 OK", NGINX_HTML)

    # authenticated routes
    if not is_authed(headers):
        if path == "/panel":
            return await send(writer, "302 Found", "", extra=["Location: /login"])
        return await send_json(writer, {"error": "unauthorized"}, "401 Unauthorized")

    if path == "/panel":
        return await send(writer, "200 OK", PANEL_HTML)
    if path == "/api/logout" and method == "POST":
        return await send_json(writer, {"ok": True},
                               extra=["Set-Cookie: session=; Path=/; Max-Age=0"])

    if path == "/api/settings":
        if method == "POST":
            SETTINGS["sni"] = str(jbody().get("sni", "")).strip()
            return await send_json(writer, {"ok": True})
        return await send_json(writer, {"sni": SETTINGS.get("sni", "")})

    if path == "/api/addresses":
        if method == "POST":
            v = str(jbody().get("addr", "")).strip()
            if v and v not in ADDRESSES:
                ADDRESSES.append(v)
            return await send_json(writer, {"ok": True})
        if method == "DELETE":
            i = jbody().get("index", -1)
            if isinstance(i, int) and 0 <= i < len(ADDRESSES):
                ADDRESSES.pop(i)
            return await send_json(writer, {"ok": True})
        return await send_json(writer, ADDRESSES)

    if path == "/api/links":
        if method == "POST":
            name = str(jbody().get("name", "user")).strip() or "user"
            uid = str(uuidlib.uuid4())
            USERS[uid] = {"name": name, "created": int(time.time())}
            _rebuild_uuid_index()
            return await send_json(writer, {"ok": True, "uuid": uid})
        if method == "DELETE":
            uid = str(jbody().get("uuid", ""))
            if uid in USERS:
                del USERS[uid]
                _rebuild_uuid_index()
            return await send_json(writer, {"ok": True})
        return await send_json(writer, [
            {"uuid": u, "name": i["name"]} for u, i in USERS.items()
        ])

    return await send(writer, "404 Not Found", NGINX_HTML)


# ------------------------------------------------------------------------------
# Dispatcher
# ------------------------------------------------------------------------------

async def handle_conn(reader, writer):
    try:
        req = await read_request(reader)
        if not req:
            return _safe_close(writer)
        method, target, headers = req
        path = urlparse(target).path
        upgrade = headers.get("upgrade", "").lower()
        if "websocket" in upgrade and path == WS_PATH:
            await handle_proxy(reader, writer, headers)
        else:
            await handle_panel(reader, writer, method, target, headers)
    except Exception:
        _safe_close(writer)


async def main():
    _seed_default_user()
    server = await asyncio.start_server(handle_conn, "0.0.0.0", PORT)
    print(f"praxiServer listening on 0.0.0.0:{PORT}  path={WS_PATH}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    import sys
    try:
        sys.stdout.reconfigure(line_buffering=True)   # unbuffered logs on Railway
    except Exception:
        pass
    try:
        import uvloop
        uvloop.install()
        print("uvloop enabled")
    except Exception:
        print("uvloop not available, using default asyncio loop")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
