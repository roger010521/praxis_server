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
            f"?encryption=none&security=tls&sni={sni}&fp=chrome&allowInsecure=1"
            f"&type=httpupgrade&host={host}&path={epath}&alpn=http%2F1.1"
            f"#{quote(info['name'])}-{i}"
        )
        out.append(link)
    return out


# ------------------------------------------------------------------------------
# Panel
# ------------------------------------------------------------------------------

LOGIN_HTML = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>praxiServer</title><style>
:root{--bg:#0a0c11;--card:#141922;--bd:#232b38;--fg:#e8ecf2;--mut:#8b98ab;
--acc:#4f8cff;--acc2:#7c5cff;--err:#ff6b6b}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;
min-height:100vh;display:flex;align-items:center;justify-content:center;
background:radial-gradient(1200px 600px at 50% -10%,#16203a 0%,var(--bg) 60%);
color:var(--fg)}
.box{background:var(--card);border:1px solid var(--bd);padding:2.2rem;
border-radius:16px;width:320px;box-shadow:0 20px 60px rgba(0,0,0,.45)}
.logo{font-size:1.5rem;font-weight:700;margin:0 0 .3rem;
background:linear-gradient(90deg,var(--acc),var(--acc2));
-webkit-background-clip:text;background-clip:text;color:transparent}
.sub{color:var(--mut);font-size:.85rem;margin:0 0 1.4rem}
label{font-size:.8rem;color:var(--mut);display:block;margin:0 0 .3rem}
input{width:100%;padding:.75rem .9rem;border-radius:10px;border:1px solid var(--bd);
background:#0c0f15;color:var(--fg);font-size:.95rem;outline:none;transition:.15s}
input:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(79,140,255,.15)}
button{width:100%;padding:.8rem;margin-top:1rem;border-radius:10px;border:0;
cursor:pointer;font-weight:600;font-size:.95rem;color:#fff;
background:linear-gradient(90deg,var(--acc),var(--acc2));transition:.15s}
button:hover{filter:brightness(1.1)}button:active{transform:translateY(1px)}
.err{color:var(--err);font-size:.82rem;margin-top:.7rem;min-height:1rem;text-align:center}
</style></head><body>
<div class=box>
 <h1 class=logo>praxiServer</h1>
 <p class=sub>Sign in to your panel</p>
 <label for=p>Password</label>
 <input id=p type=password placeholder="••••••••" autocomplete=current-password>
 <button onclick=login()>Sign in</button>
 <div id=e class=err></div>
</div>
<script>
async function login(){
 const e=document.getElementById('e');e.textContent='';
 const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({password:document.getElementById('p').value})});
 if(r.ok){location.href='/panel'}else{e.textContent='Wrong password'}
}
document.getElementById('p').addEventListener('keydown',e=>{if(e.key==='Enter')login()});
document.getElementById('p').focus();
</script></body></html>"""

PANEL_HTML = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>praxiServer · panel</title><style>
:root{--bg:#0a0c11;--card:#141922;--card2:#0f131b;--bd:#232b38;--fg:#e8ecf2;
--mut:#8b98ab;--acc:#4f8cff;--acc2:#7c5cff;--grn:#2ecc71;--red:#ff5c5c}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;
background:radial-gradient(1200px 500px at 100% -10%,#16203a 0%,var(--bg) 55%);
color:var(--fg);min-height:100vh}
.wrap{max-width:860px;margin:0 auto;padding:1.2rem}
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:1.2rem}
.logo{font-size:1.35rem;font-weight:700;margin:0;
background:linear-gradient(90deg,var(--acc),var(--acc2));
-webkit-background-clip:text;background-clip:text;color:transparent}
.card{background:var(--card);border:1px solid var(--bd);border-radius:16px;
padding:1.2rem;margin-bottom:1rem;box-shadow:0 8px 30px rgba(0,0,0,.25)}
.card h3{margin:0 0 .2rem;font-size:1rem}
.card p{margin:0 0 .9rem;color:var(--mut);font-size:.82rem}
.row{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center}
input{flex:1;min-width:0;padding:.7rem .85rem;border-radius:10px;border:1px solid var(--bd);
background:var(--card2);color:var(--fg);font-size:.9rem;outline:none;transition:.15s}
input:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(79,140,255,.15)}
button{padding:.7rem 1rem;border-radius:10px;border:0;cursor:pointer;font-weight:600;
font-size:.85rem;color:#fff;background:#2a3444;transition:.15s;white-space:nowrap}
button:hover{filter:brightness(1.15)}button:active{transform:translateY(1px)}
.b-acc{background:linear-gradient(90deg,var(--acc),var(--acc2))}
.b-grn{background:var(--grn)}.b-red{background:var(--red)}
.b-ghost{background:transparent;border:1px solid var(--bd);color:var(--mut)}
.chip{display:flex;align-items:center;justify-content:space-between;gap:.5rem;
background:var(--card2);border:1px solid var(--bd);border-radius:10px;
padding:.55rem .8rem;margin-top:.5rem}
.chip code{color:#9cc4ff;font-size:.85rem;word-break:break-all}
.empty{color:var(--mut);font-size:.85rem;margin-top:.5rem}
.user{display:flex;align-items:center;justify-content:space-between;gap:.6rem;
padding:.7rem 0;border-top:1px solid var(--bd)}
.user:first-child{border-top:0}
.uname{font-weight:600}.uuid{color:var(--mut);font-size:.72rem;word-break:break-all}
.uacts{display:flex;gap:.4rem;flex-shrink:0}
.iconbtn{padding:.5rem .7rem;font-size:.78rem}
#toast{position:fixed;left:50%;bottom:1.3rem;transform:translateX(-50%) translateY(120%);
background:var(--grn);color:#04210f;padding:.7rem 1.2rem;border-radius:10px;
font-weight:600;font-size:.85rem;transition:.25s;box-shadow:0 8px 24px rgba(0,0,0,.4);z-index:9}
#toast.show{transform:translateX(-50%) translateY(0)}
@media(max-width:520px){.user{flex-direction:column;align-items:flex-start}}
</style></head><body>
<div class=wrap>
 <header>
  <h1 class=logo>praxiServer</h1>
  <button class=b-ghost onclick=logout()>Logout</button>
 </header>

 <div class=card>
  <h3>Bug SNI</h3>
  <p>Domain your ISP lets through. Leave empty to use the server host.</p>
  <div class=row>
   <input id=sni placeholder="your.bug.host">
   <button class=b-grn onclick=saveSni()>Save</button>
  </div>
 </div>

 <div class=card>
  <h3>Clean IPs / addresses</h3>
  <p>Extra addresses to generate alternative configs (optional).</p>
  <div class=row>
   <input id=addr placeholder="104.21.x.x or a domain">
   <button class=b-grn onclick=addAddr()>Add</button>
  </div>
  <div id=addrs></div>
 </div>

 <div class=card>
  <h3>Users</h3>
  <p>Each user gets a subscription link with all configs.</p>
  <div class=row>
   <input id=uname placeholder="user name">
   <button class=b-acc onclick=addUser()>+ Add user</button>
  </div>
  <div id=users style=margin-top:.6rem></div>
 </div>
</div>
<div id=toast></div>

<script>
const j=(u,o)=>fetch(u,o).then(r=>r.json());
const esc=s=>s.replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function toast(m){const t=document.getElementById('toast');t.textContent=m;
 t.classList.add('show');clearTimeout(t._t);t._t=setTimeout(()=>t.classList.remove('show'),1800)}
function copy(u){navigator.clipboard.writeText(u).then(()=>toast('Copied ✓'))}
async function load(){
 const s=await j('/api/settings');document.getElementById('sni').value=s.sni||'';
 const a=await j('/api/addresses');
 document.getElementById('addrs').innerHTML=a.length?a.map((x,i)=>
  `<div class=chip><code>${esc(x)}</code>
   <button class="b-red iconbtn" onclick=delAddr(${i})>Remove</button></div>`).join(''):
  '<div class=empty>No extra addresses.</div>';
 const u=await j('/api/links');
 document.getElementById('users').innerHTML=u.length?u.map(x=>{
  const sub=location.origin+'/sub/'+x.uuid;
  return `<div class=user><div style=min-width:0>
   <div class=uname>${esc(x.name)}</div><div class=uuid>${sub}</div></div>
   <div class=uacts>
    <button class="b-acc iconbtn" onclick="copy('${sub}')">Copy sub</button>
    <button class="b-red iconbtn" onclick="delUser('${x.uuid}')">Delete</button>
   </div></div>`}).join(''):'<div class=empty>No users yet.</div>';
}
async function saveSni(){await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({sni:document.getElementById('sni').value.trim()})});toast('Saved ✓');load()}
async function addAddr(){const el=document.getElementById('addr');const v=el.value.trim();if(!v)return;
 await fetch('/api/addresses',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({addr:v})});el.value='';load()}
async function delAddr(i){await fetch('/api/addresses',{method:'DELETE',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({index:i})});load()}
async function addUser(){const el=document.getElementById('uname');const v=el.value.trim()||'user';
 await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({name:v})});el.value='';load()}
async function delUser(u){if(!confirm('Delete this user?'))return;
 await fetch('/api/links',{method:'DELETE',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({uuid:u})});load()}
function logout(){fetch('/api/logout',{method:'POST'}).then(()=>location.href='/login')}
document.getElementById('uname').addEventListener('keydown',e=>{if(e.key==='Enter')addUser()});
document.getElementById('addr').addEventListener('keydown',e=>{if(e.key==='Enter')addAddr()});
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


async def keepalive():
    """Ping the public URL every 5 min so free hosts don't spin down.

    On Railway the public domain is auto-detected from RAILWAY_PUBLIC_DOMAIN.
    Otherwise set KEEPALIVE_URL to your public https URL.
    """
    import urllib.request
    domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "").strip()
    url = os.environ.get("KEEPALIVE_URL", "").strip()
    if not url and domain:
        url = f"https://{domain}/health"
    if not url:
        print("keep-alive: disabled (set KEEPALIVE_URL to enable)")
        return
    print(f"keep-alive: pinging {url} every 5 min")
    loop = asyncio.get_event_loop()
    while True:
        await asyncio.sleep(300)
        try:
            await loop.run_in_executor(
                None, lambda: urllib.request.urlopen(url, timeout=15).read())
        except Exception:
            pass


async def main():
    _seed_default_user()
    asyncio.create_task(keepalive())
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
