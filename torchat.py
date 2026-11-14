#!/usr/bin/env python3
"""torchat - private chat with anyone in the world. No servers, no browser.

  python3 torchat.py            opens a window (or a simple text screen on phones/servers)

How it works
  1. One person picks "Start a chat" and gets an 8-word pairing code.
  2. They tell the code to ONE friend (phone call, message, in person).
  3. The friend picks "Join a chat" and types the words. Both compare a short
     safety code, then chat. Text, images and documents are all end-to-end encrypted.

Security design
  * Peer-to-peer over a Tor onion service: works worldwide, behind any NAT or
    firewall, hides both IP addresses, and no server ever stores or sees anything.
  * The 8 words (77 random bits + checksum) are stretched with scrypt into the onion
    address, a client-authorization key and a handshake secret, so only someone who
    knows the code can even find or enter the chat. The code works once.
  * Handshake: ephemeral X25519, transcript-bound HKDF, mutual key confirmation and a
    human-checkable safety code (you must confirm it before anything is sent).
  * Signal-style Double Ratchet (forward secrecy + recovery) with ChaCha20-Poly1305.
  * No local web server, no browser, no open network port: the app is just a window
    (or terminal) plus a private unix socket to Tor.
  * Files: 50 MB max, SHA-256 verified, stored under random names in a private temp
    folder (wiped on exit), JPEG/PNG metadata scrubbed before sending, nothing is
    ever opened automatically, executable types are flagged.
Limits: 1:1 chat, both people online at the same time, no professional audit, cannot
protect a device that is already compromised.
"""
import argparse, atexit, base64, collections, hashlib, hmac, json, os, queue, re
import resource, secrets, shutil, signal, socket, stat, struct, subprocess, sys, tempfile
import threading, time, unicodedata, _thread

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ======================================================================== core (crypto, framing, files, safety)

PORT = 7777

MAXMSG = 2000

MAXFRAME = 16384

E, P, PF, NE = (serialization.Encoding.Raw, serialization.PublicFormat.Raw,
                serialization.PrivateFormat.Raw, serialization.NoEncryption())

def pub(k): return k.public_key().public_bytes(E, P)

def priv(k): return k.private_bytes(E, PF, NE)

def load_pub(b): return X25519PublicKey.from_public_bytes(b)

def hkdf(ikm, salt, info, n=32): return HKDF(hashes.SHA256(), n, salt or None, info).derive(ikm)

def mac(k, d): return hmac.new(k, d, hashlib.sha256).digest()

def dh(sk, peer_pub_bytes):
    out = sk.exchange(load_pub(peer_pub_bytes))      # raises ValueError on low-order points
    if out == b"\x00" * 32:
        raise ValueError("weak key")
    return out

def kdf_rk(rk, dh_out):
    o = hkdf(dh_out, rk, b"torchat3-rk", 64)
    return o[:32], o[32:]

def kdf_ck(ck):
    return mac(ck, b"\x02"), mac(ck, b"\x01")

def msg_keys(mk):
    o = hkdf(mk, b"", b"torchat3-msg", 44)
    return o[:32], o[32:]

class Ratchet:
    """Double Ratchet over a reliable, ordered stream (no skipped-key storage needed)."""
    def __init__(self, rk, my_ratchet, peer_ratchet_pub, initiator):
        self.rk, self.dhs, self.dhr = rk, my_ratchet, None
        self.cks = self.ckr = None
        self.ns = self.nr = 0
        if initiator:
            self.dhr = peer_ratchet_pub
            self.rk, self.cks = kdf_rk(self.rk, dh(self.dhs, self.dhr))

    @property
    def can_send(self): return self.cks is not None

    def encrypt(self, pt):
        hdr = pub(self.dhs) + struct.pack(">I", self.ns)
        self.cks, mk = kdf_ck(self.cks)
        self.ns += 1
        k, nonce = msg_keys(mk)
        return hdr + ChaCha20Poly1305(k).encrypt(nonce, pt, hdr)

    def decrypt(self, frame):
        if len(frame) < 36 + 16:
            raise ValueError("short frame")
        hdr, ct = frame[:36], frame[36:]
        their, n = hdr[:32], struct.unpack(">I", hdr[32:])[0]
        rk, dhs, dhr, cks, ckr, ns, nr = self.rk, self.dhs, self.dhr, self.cks, self.ckr, self.ns, self.nr
        if their != dhr:                                   # DH ratchet step
            rk, ckr = kdf_rk(rk, dh(dhs, their)); dhr = their; nr = 0
            dhs = X25519PrivateKey.generate()
            rk, cks = kdf_rk(rk, dh(dhs, dhr)); ns = 0
        if ckr is None or n != nr:
            raise ValueError("out of order / replay")
        ckr, mk = kdf_ck(ckr)
        k, nonce = msg_keys(mk)
        pt = ChaCha20Poly1305(k).decrypt(nonce, ct, hdr)   # raises InvalidTag if forged
        self.rk, self.dhs, self.dhr, self.cks, self.ckr, self.ns, self.nr = rk, dhs, dhr, cks, ckr, ns, nr + 1
        return pt

def recvn(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise ConnectionError("connection closed")
        buf += c
    return buf

def send_frame(s, data): s.sendall(struct.pack(">I", len(data)) + data)

def recv_frame(s):
    n = struct.unpack(">I", recvn(s, 4))[0]
    if n > MAXFRAME:
        raise ValueError("frame too large")
    return recvn(s, n)

def pad_plain(kind, body):
    raw = bytes([kind]) + struct.pack(">H", len(body)) + body
    return raw + b"\x00" * (-len(raw) % 256)

def clean(s):
    return "".join(c for c in s if unicodedata.category(c)[0] != "C" and c not in "\u2028\u2029")

def handshake(sock, role, passphrase=""):
    e, r = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    mine = b"TC3" + pub(e) + pub(r)
    sock.sendall(mine)
    theirs = recvn(sock, 67)
    if theirs[:3] != b"TC3":
        raise ValueError("not a torchat3 peer")
    transcript = hashlib.sha256(b"".join(sorted([mine, theirs]))).digest()
    shared = dh(e, theirs[3:35])
    pw = b""
    if passphrase:
        pw = Scrypt(salt=b"torchat3-passphrase", length=32, n=2**15, r=8, p=1).derive(passphrase.encode())
    master = hkdf(shared, pw, b"torchat3-master" + transcript)
    confk = hkdf(master, b"", b"confirm")
    other = "join" if role == "host" else "host"
    sock.sendall(mac(confk, role.encode() + transcript))
    if not hmac.compare_digest(recvn(sock, 32), mac(confk, other.encode() + transcript)):
        raise ValueError("key confirmation failed (wrong passphrase or tampering)")
    sas = hkdf(master, b"", b"sas", 10).hex()
    sas = " ".join(sas[i:i + 4] for i in range(0, 20, 4))
    ratchet = Ratchet(hkdf(master, b"", b"root"), r, theirs[35:67], role == "host")
    return ratchet, sas

def b32(b): return base64.b32encode(b).decode().rstrip("=")

def private_tmp():
    base = os.environ.get("XDG_RUNTIME_DIR") or ("/dev/shm" if os.path.isdir("/dev/shm") else None)
    d = tempfile.mkdtemp(prefix="tc.", dir=base)
    os.chmod(d, 0o700)
    return d

def harden():
    try: resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception: pass
    try:
        import ctypes; ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)       # PR_SET_DUMPABLE=0
    except Exception: pass

MAXFILE = 50 * 1024 * 1024

MAXTOTAL = 200 * 1024 * 1024

MAXIMG = 25 * 1024 * 1024

CHUNK = 8000

EXEC_EXT = {".exe", ".msi", ".bat", ".cmd", ".com", ".scr", ".ps1", ".vbs", ".js", ".jse", ".jar", ".apk",
            ".sh", ".app", ".dmg", ".lnk", ".reg", ".hta", ".py", ".pif", ".dll", ".deb", ".rpm", ".appimage"}

LIMITS = {0: MAXMSG, 1: 0, 2: 2000, 3: 8 + CHUNK, 4: 40}

def sniff(b):
    if b.startswith(b"\x89PNG\r\n\x1a\n"): return "image/png"
    if b.startswith(b"\xff\xd8\xff"): return "image/jpeg"
    if b[:6] in (b"GIF87a", b"GIF89a"): return "image/gif"
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP": return "image/webp"
    return None

def safe_name(n):
    n = os.path.basename(str(n).replace("\\", "/"))
    n = "".join(c for c in n if unicodedata.category(c)[0] != "C").strip(" .")
    return n[:120] or "file"

def human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB": return ("%d %s" % (n, u)) if u == "B" else ("%.1f %s" % (n, u))
        n /= 1024

PNG_KEEP = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP",
            b"sBIT", b"bKGD", b"pHYs", b"acTL", b"fcTL", b"fdAT"}

def strip_png(b):
    out, i = [b[:8]], 8
    while i + 12 <= len(b):
        n = struct.unpack(">I", b[i:i + 4])[0]; typ = b[i + 4:i + 8]; end = i + 12 + n
        if end > len(b): raise ValueError("truncated png")
        if typ in PNG_KEEP: out.append(b[i:end])
        i = end
        if typ == b"IEND": return b"".join(out)
    raise ValueError("png without IEND")

def exif_orientation(payload):                 # payload starts with b"Exif\0\0"
    try:
        tiff = payload[6:]; e = "<" if tiff[:2] == b"II" else ">"
        off = struct.unpack(e + "I", tiff[4:8])[0]
        cnt = struct.unpack(e + "H", tiff[off:off + 2])[0]
        for k in range(cnt):
            ent = tiff[off + 2 + 12 * k: off + 14 + 12 * k]
            tag = struct.unpack(e + "H", ent[:2])[0]
            if tag == 0x0112: return struct.unpack(e + "H", ent[8:10])[0]
    except Exception:
        pass
    return None

def strip_jpeg(b):
    if b[:2] != b"\xff\xd8": raise ValueError("not jpeg")
    out, i, orient = [b"\xff\xd8"], 2, None
    while True:
        if i + 2 > len(b) or b[i] != 0xFF: raise ValueError("bad marker")
        m = b[i + 1]
        if m == 0xFF: i += 1; continue
        if m == 0xD9: out.append(b"\xff\xd9"); break                 # EOI: everything after is dropped
        if m == 0x01 or 0xD0 <= m <= 0xD8: out.append(b[i:i + 2]); i += 2; continue
        if i + 4 > len(b): raise ValueError("truncated")
        n = struct.unpack(">H", b[i + 2:i + 4])[0]; end = i + 2 + n
        if n < 2 or end > len(b): raise ValueError("truncated")
        seg = b[i:end]
        if m == 0xE1 and seg[4:10] == b"Exif\0\0": orient = exif_orientation(seg[4:])
        if m in (0xE0, 0xEE) or not (0xE1 <= m <= 0xEF or m == 0xFE): out.append(seg)
        i = end
        if m == 0xDA:                                                  # entropy-coded scan data
            k = i
            while True:
                k = b.find(b"\xff", k)
                if k < 0 or k + 1 >= len(b): raise ValueError("truncated scan")
                x = b[k + 1]
                if x == 0 or 0xD0 <= x <= 0xD7: k += 2
                elif x == 0xFF: k += 1
                else: break
            out.append(b[i:k]); i = k
    if orient and orient != 1:
        payload = b"Exif\0\0MM\0*\0\0\0\x08\0\x01" + struct.pack(">HHIHH", 0x0112, 3, 1, orient, 0) + b"\0\0\0\0"
        seg = b"\xff\xe1" + struct.pack(">H", 2 + len(payload)) + payload
        out.insert(2 if len(out) > 1 and out[1][:2] == b"\xff\xe0" else 1, seg)
    return b"".join(out)

def read_exact(f, n):
    buf = bytearray()
    while len(buf) < n:
        c = f.read(n - len(buf))
        if not c: raise ConnectionError("upload interrupted")
        buf += c
    return bytes(buf)

def wipe_dir(d):
    """Best effort: overwrite files with zeros, then delete. (Flash storage can't be guaranteed.)"""
    for root, _, files in os.walk(d):
        for f in files:
            pth = os.path.join(root, f)
            try:
                if os.path.islink(pth): continue
                left = os.path.getsize(pth)
                with open(pth, "r+b") as fh:
                    while left > 0:
                        fh.write(b"\0" * min(left, 1 << 20)); left -= 1 << 20
                    fh.flush(); os.fsync(fh.fileno())
            except OSError:
                pass
    shutil.rmtree(d, ignore_errors=True)

def sweep_stale():
    """Remove leftovers of earlier runs that were killed (their pid is gone)."""
    bases = {os.environ.get("XDG_RUNTIME_DIR"), "/dev/shm", tempfile.gettempdir()}
    for base in filter(None, bases):
        try: names = os.listdir(base)
        except OSError: continue
        for n in names:
            if not n.startswith("tc."): continue
            d = os.path.join(base, n)
            try:
                st = os.lstat(d)
                if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid(): continue
                os.kill(int(open(os.path.join(d, "pid")).read()), 0)
            except ProcessLookupError: wipe_dir(d)
            except (OSError, ValueError): continue

def _safe_dir(path):
    """True only for a real directory (not a symlink) that is ours and not writable by group/others."""
    try:
        st = os.lstat(path)
        return stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not (st.st_mode & 0o022)
    except OSError:
        return False

CACHE_FILES = ("cached-certs", "cached-microdesc-consensus", "cached-microdescs", "cached-microdescs.new", "state")

def cache_dir():
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "torchat", "tor")

def _cache_ready(create):
    d = cache_dir(); parent = os.path.dirname(d)
    if create:
        try: os.makedirs(d, mode=0o700, exist_ok=True)
        except OSError: return False
    return _safe_dir(parent) and _safe_dir(d)

def clear_cache():
    """Delete ONLY the files we created in the cache folder (never a whole directory tree)."""
    d = cache_dir()
    if _safe_dir(d):
        for n in CACHE_FILES:
            for suffix in ("", ".tmp"):
                try: os.unlink(os.path.join(d, n + suffix))
                except OSError: pass
        for p in (d, os.path.dirname(d)):
            try: os.rmdir(p)
            except OSError: pass

def find_tor():
    """Resolve tor once to an absolute path; refuse writable-by-everyone locations (PATH hijack)."""
    p = shutil.which("tor")
    if not p: raise RuntimeError("tor not found - run setup.sh")
    real = os.path.realpath(p)
    for q in (real, os.path.dirname(real)):
        if os.stat(q).st_mode & stat.S_IWOTH:
            raise RuntimeError("refusing to run tor from a world-writable location: %s" % real)
    return real

SOCKS_ERRORS = {
    4: "host unreachable", 5: "connection refused", 6: "timed out",
    0xF0: "host not found - their app is not running, has not finished publishing (can take ~1 minute), or this invite is from an OLDER run (every restart makes a new invite)",
    0xF1: "host's address data is invalid",
    0xF2: "could not reach the host's entry point (introduction failed)",
    0xF3: "meeting point failed (rendezvous failed)",
    0xF4: "host wants an invite key and did not accept ours (missing client auth)",
    0xF5: "the invite key does not match - wrong invite or an OLDER invite (wrong client auth)",
    0xF6: "invalid host address in the invite",
    0xF7: "host did not answer in time (introduction timed out)",
}

class SocksError(ConnectionError):
    def __init__(self, code):
        super().__init__(SOCKS_ERRORS.get(code, "tor refused the connection (code %d)" % code)); self.code = code

def socks5_unix(path, host, dport):
    """SOCKS5 over Tor's private unix socket (no TCP port that other programs could use)."""
    s = socket.socket(socket.AF_UNIX); s.settimeout(120)
    try:
        s.connect(path)
        s.sendall(b"\x05\x01\x00")
        if recvn(s, 2) != b"\x05\x00": raise ConnectionError("socks handshake")
        h = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", dport))
        r = recvn(s, 4)
        if r[1] != 0: raise SocksError(r[1])
        recvn(s, {1: 4, 4: 16}.get(r[3]) or recvn(s, 1)[0]); recvn(s, 2)
        s.settimeout(None)
        return s
    except BaseException:
        s.close(); raise

class Flood(Exception): pass

def unpad(pt):
    kind, n = pt[0], struct.unpack(">H", pt[1:3])[0]
    if kind not in LIMITS or n > LIMITS[kind] or 3 + n > len(pt): raise ValueError("bad frame")
    return kind, pt[3:3 + n]

class Chat:
    def __init__(self, app, sock, ratchet, role):
        self.app, self.s, self.r, self.role = app, sock, ratchet, role
        self.lock = threading.Lock()
        self.inc = None; self.skip = None; self.seen = set()

    @property
    def ready(self): return self.r.can_send

    def start(self):
        threading.Thread(target=self._recv, daemon=True).start()
        if self.role == "host": self._send(1, b"")

    def _send(self, kind, body):
        with self.lock:
            send_frame(self.s, self.r.encrypt(pad_plain(kind, body)))

    def send_text(self, text):
        body = text.encode()
        if not body or len(body) > MAXMSG: raise ValueError("message empty or longer than %d bytes" % MAXMSG)
        self._send(0, body)
        self.app.emit(kind="out", text=text)

    def send_upload(self, name, length, rfile):
        app, name = self.app, safe_name(name)
        if length > MAXFILE: raise ValueError("file too large (max %s)" % human(MAXFILE))
        if app.sent_total + length > MAXTOTAL: raise ValueError("session transfer limit reached")
        first = read_exact(rfile, min(CHUNK, length))
        mime, scrubbed, raw = sniff(first), None, None
        if mime in ("image/jpeg", "image/png") and length <= MAXIMG:
            raw = first + read_exact(rfile, length - len(first))
            try:
                raw = strip_jpeg(raw) if mime == "image/jpeg" else strip_png(raw); scrubbed = True
            except ValueError:                            # never fall back to sending the original photo
                raise ValueError("this photo's hidden details (location, camera) could not be removed, so it was NOT sent")
        size = len(raw) if raw is not None else length
        fid = os.urandom(8); fhex = fid.hex(); h = hashlib.sha256()
        app.transfers[fhex] = {"name": name, "size": size, "done": 0, "dir": "out"}
        started = False
        try:
            self._send(2, json.dumps({"id": fhex, "name": name, "size": size}).encode()); started = True
            def chunks():
                if raw is not None:
                    for k in range(0, len(raw), CHUNK): yield raw[k:k + CHUNK]
                else:
                    if first: yield first
                    got = len(first)
                    while got < size:
                        c = read_exact(rfile, min(CHUNK, size - got)); got += len(c); yield c
            sent = 0
            for chunk in chunks():
                h.update(chunk); self._send(3, fid + chunk); sent += len(chunk)
                app.transfers[fhex]["done"] = sent
            self._send(4, fid + h.digest())
        except BaseException:
            if started:                                   # tell the peer to drop the half-received file
                try: self._send(4, fid + b"\0" * 32)
                except Exception: pass
            raise
        finally:
            app.transfers.pop(fhex, None)
        app.sent_total += size
        preview = raw is not None
        if preview:
            pth = os.path.join(app.recvdir, fhex + ".bin")
            with open(pth, "wb") as f: f.write(raw)
            app.files[fhex] = {"name": name, "size": size, "mime": mime, "path": pth, "image": True}
        app.emit(kind="file_out", fid=fhex if preview else None, name=name, size=size, image=preview,
                  scrubbed=scrubbed, warn=os.path.splitext(name)[1].lower() in EXEC_EXT)

    def _abort_incoming(self):
        if self.inc:
            try: self.inc["fh"].close()
            except OSError: pass
            try: os.remove(self.inc["path"])
            except OSError: pass
            self.app.transfers.pop(self.inc["lid"], None); self.inc = None

    def _recv(self):
        app = self.app
        times = collections.deque()
        try:
            while True:
                frame = recv_frame(self.s)          # block on the network WITHOUT holding the lock
                with self.lock:
                    pt = self.r.decrypt(frame)
                kind, body = unpad(pt)
                if kind != 3:                          # rate-limit everything except file data
                    now = time.time(); times.append(now)
                    while times and now - times[0] > 10: times.popleft()
                    if len(times) > 100: raise Flood("peer is flooding")
                if kind == 0:
                    app.emit(kind="in", text=clean(body.decode("utf-8", "replace")))
                elif kind == 2:
                    m = json.loads(body.decode()); fid, size = m["id"], m["size"]
                    if not (isinstance(fid, str) and re.fullmatch("[0-9a-f]{16}", fid)
                            and isinstance(size, int) and 0 <= size <= MAXFILE and isinstance(m["name"], str)):
                        raise ValueError("bad file header")
                    name = safe_name(m["name"])
                    if fid in self.seen or len(self.seen) >= 5000: raise ValueError("file id reused / too many offers")
                    self.seen.add(fid)
                    if self.inc: self._abort_incoming()          # previous transfer was cancelled
                    if app.recv_total + size > MAXTOTAL:
                        self.skip = fid; app.emit(kind="sys", text="Refused incoming file '%s' (session limit)" % name); continue
                    lid = os.urandom(8).hex()                  # OUR id: the peer never chooses names/keys on our side
                    while lid in app.files: lid = os.urandom(8).hex()
                    path = os.path.join(app.recvdir, lid + ".bin")
                    self.inc = {"id": fid, "lid": lid, "name": name, "size": size, "done": 0, "path": path,
                                "fh": open(path, "wb"), "h": hashlib.sha256(), "head": b""}
                    app.transfers[lid] = {"name": name, "size": size, "done": 0, "dir": "in"}
                elif kind == 3:
                    fid = body[:8].hex()
                    if fid == self.skip: continue
                    i = self.inc
                    if not i or i["id"] != fid: raise ValueError("unexpected chunk")
                    data = body[8:]
                    i["done"] += len(data)
                    if i["done"] > i["size"]: raise ValueError("file larger than announced")
                    if len(i["head"]) < 16: i["head"] += data[:16]
                    i["h"].update(data); i["fh"].write(data)
                    app.transfers[i["lid"]]["done"] = i["done"]
                elif kind == 4:
                    fid = body[:8].hex()
                    if fid == self.skip: self.skip = None; continue
                    i = self.inc
                    if not i or i["id"] != fid: raise ValueError("unexpected end")
                    i["fh"].close()
                    ok = i["done"] == i["size"] and hmac.compare_digest(i["h"].digest(), body[8:40])
                    app.transfers.pop(i["lid"], None); self.inc = None
                    if not ok:
                        os.remove(i["path"]); app.emit(kind="sys", text="File '%s' was cancelled or failed its integrity check - discarded." % i["name"]); continue
                    mime, size, inline = sniff(i["head"]), i["size"], False
                    if mime in ("image/png", "image/jpeg") and size <= MAXIMG:
                        try:                                   # re-scrub + structurally validate received images
                            with open(i["path"], "rb") as fh: data = fh.read()
                            data = strip_png(data) if mime == "image/png" else strip_jpeg(data)
                            with open(i["path"], "wb") as fh: fh.write(data)
                            size, inline = len(data), True
                        except (ValueError, OSError):
                            app.emit(kind="sys", text="Image '%s' is malformed - preview disabled." % i["name"])
                    elif mime == "image/gif":
                        inline = True
                    app.recv_total += i["size"]
                    app.files[i["lid"]] = {"name": i["name"], "size": size, "mime": mime, "path": i["path"], "image": inline}
                    app.emit(kind="file_in", fid=i["lid"], name=i["name"], size=size, image=inline,
                              warn=os.path.splitext(i["name"])[1].lower() in EXEC_EXT)
        except ConnectionError:
            app.emit(kind="sys", text="Peer disconnected.")
        except Flood:
            app.emit(kind="sys", text="Session closed - the peer was flooding you.")
        except Exception as ex:
            app.emit(kind="sys", text="Session closed - authentication/protocol failure (%s)." % type(ex).__name__)
        self._abort_incoming()
        try: self.s.close()
        except OSError: pass
        app.set_stage("closed")


# ======================================================================== onion keys
def onion_from_seed(seed32):
    """Deterministic v3 onion address + public key from a 32-byte ed25519 seed."""
    pk = Ed25519PrivateKey.from_private_bytes(seed32).public_key().public_bytes(E, P)
    chk = hashlib.sha3_256(b".onion checksum" + pk + b"\x03").digest()[:2]
    return base64.b32encode(pk + chk + b"\x03").decode().lower(), pk

def hs_key_files(seed32):
    """The two files Tor reads from a HiddenServiceDir so the onion address comes from our seed."""
    _, pk = onion_from_seed(seed32)
    h = hashlib.sha512(seed32).digest()
    a = bytearray(h[:32]); a[0] &= 248; a[31] &= 127; a[31] |= 64
    secret = b"== ed25519v1-secret: type0 ==\0\0\0" + bytes(a) + h[32:]
    public = b"== ed25519v1-public: type0 ==\0\0\0" + pk
    return secret, public


# ======================================================================== bridges / firewall
BRIDGE_PLUGINS = {"obfs4": ("obfs4proxy", "lyrebird"), "meek_lite": ("obfs4proxy", "lyrebird"),
                  "snowflake": ("snowflake-client",), "webtunnel": ("webtunnel-client", "webtunnel")}

def _plugin_exe(names):
    for n in names:
        p = shutil.which(n)
        if not p: continue
        real = os.path.realpath(p)
        if any(os.stat(q).st_mode & stat.S_IWOTH for q in (real, os.path.dirname(real))): continue
        if re.fullmatch(r"[A-Za-z0-9_./-]+", real): return real
    return None

def load_bridges(path):
    """Read Tor bridge lines (from bridges.torproject.org) for networks that block Tor. Strictly validated."""
    with open(path, "rb") as f: raw = f.read(20001)
    if len(raw) > 20000: raise ValueError("bridge file is too large")
    lines, plugins = [], {}
    for ln in raw.decode("utf-8", "replace").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"): continue
        if ln.lower().startswith("bridge "): ln = ln[7:].strip()
        if len(ln) > 600 or not re.fullmatch(r"[A-Za-z0-9_.:,=\[\]/+@~ -]+", ln):
            raise ValueError("a bridge line has unsupported characters")
        first = ln.split()[0]
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", first):          # pluggable transport line
            if first not in BRIDGE_PLUGINS: raise ValueError("unsupported bridge type '%s'" % first)
            exe = _plugin_exe(BRIDGE_PLUGINS[first])
            if not exe: raise ValueError("'%s' bridges need the program %s - install it first" % (first, " or ".join(BRIDGE_PLUGINS[first])))
            plugins[first] = exe
        lines.append(ln)
    if not lines: raise ValueError("no bridge lines found in the file")
    if len(lines) > 20: raise ValueError("too many bridge lines (max 20)")
    return lines, plugins


# ======================================================================== Tor process
class Tor:
    """One private Tor process (client and/or onion service) in a wiped temp dir.
       * pinned absolute tor binary, private unix sockets only (no TCP ports)
       * reuses Tor's PUBLIC network cache between runs for fast starts (--no-cache to disable)
       * live progress + plain-English diagnostics for the UI"""
    use_cache = True
    debug = False
    stall_after = 45
    bridges, plugins, firewall = [], {}, False
    HS_INTEREST = re.compile(r"(?i)descriptor|introduc|rendezv|hsdir|auth|intro point|publish|upload|fetch|unable|fail")

    def __init__(self, ui):
        self.ui, self.dir, self.proc, self.srv = ui, private_tmp(), None, None
        self.done, self.error = threading.Event(), None
        self.stopped, self.role, self.t_start = False, "", time.time()
        with open(os.path.join(self.dir, "pid"), "w") as f: f.write(str(os.getpid()))
        atexit.register(self.stop)

    # ---- cache of PUBLIC Tor network data (no keys, no chats, no codes)
    def _restore_cache(self):
        if not _cache_ready(False): return
        src, dst = cache_dir(), self.dir + "/data"
        for n in CACHE_FILES:
            p = os.path.join(src, n)
            try:
                st = os.lstat(p)
                if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_size > 200 * 1024 * 1024: continue
                with open(p, "rb") as fi, open(os.path.join(dst, n), "wb") as fo: shutil.copyfileobj(fi, fo)
                os.chmod(os.path.join(dst, n), 0o600)
            except OSError: pass

    def _save_cache(self):
        src = self.dir + "/data"
        if not os.path.isfile(os.path.join(src, "cached-microdesc-consensus")): return
        try:
            if not _cache_ready(True): return
            dst = cache_dir()
            os.chmod(dst, 0o700); os.chmod(os.path.dirname(dst), 0o700)
            for n in CACHE_FILES:
                p = os.path.join(src, n)
                if not os.path.isfile(p): continue
                tmp = os.path.join(dst, n + ".tmp")
                try: os.unlink(tmp)                              # a planted symlink is removed, never followed
                except FileNotFoundError: pass
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(fd, "wb") as fo, open(p, "rb") as fi: shutil.copyfileobj(fi, fo)
                os.replace(tmp, os.path.join(dst, n))
        except OSError: pass

    def stop(self):
        self.stopped = True
        if self.srv is not None:                                # wakes a host still waiting in accept()
            try: self.srv.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            self.srv.close()
        p = self.proc
        if p and p.poll() is None:
            p.terminate()
            try: p.wait(5)
            except subprocess.TimeoutExpired: p.kill(); p.wait()
        if self.use_cache and p is not None: self._save_cache()
        wipe_dir(self.dir)

    def _net_lines(self):
        out = []
        if Tor.firewall: out.append("ReachableAddresses *:80,*:443")          # networks that only allow web ports
        if Tor.bridges:
            out.append("UseBridges 1")
            for t, exe in Tor.plugins.items(): out.append("ClientTransportPlugin %s exec %s" % (t, exe))
            for b in Tor.bridges: out.append("Bridge " + b)
        return out

    def _start(self, lines):
        d = self.dir
        tor_bin = find_tor()
        os.makedirs(d + "/data", mode=0o700, exist_ok=True)
        if self.use_cache: self._restore_cache()
        with open(d + "/torrc", "w") as f:
            f.write("\n".join(["DataDirectory %s/data" % d, "Log notice file %s/tor.log" % d,
                               "AvoidDiskWrites 1", "Log [REND]info file %s/hs.log" % d]
                              + self._net_lines() + lines) + "\n")
        self.t_start = time.time()
        self.proc = subprocess.Popen([tor_bin, "-f", d + "/torrc"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        threading.Thread(target=self._watch, daemon=True).start()

    def _read(self, name):
        try:
            with open(self.dir + "/" + name) as f: return f.read()
        except OSError: return ""

    def _watch(self):
        ui = self.ui
        rep, det, tail = (getattr(ui, n, None) for n in ("set_progress", "set_detail", "set_tail"))
        last, last_change, shown, pos1, pos2 = -1, time.time(), "", 0, 0
        while not self.stopped:
            if self.proc.poll() is not None:
                if not self.stopped:
                    self.error = self.error or "tor exited - is it installed and working?"; self.done.set()
                return
            txt, hs = self._read("tor.log"), self._read("hs.log")
            if Tor.debug:
                for tag, body, pos in (("tor", txt, pos1), ("hs", hs, pos2)):
                    for ln in body[pos:].splitlines(): print("[%s] %s" % (tag, ln), file=sys.stderr, flush=True)
                pos1, pos2 = len(txt), len(hs)
            found = re.findall(r"Bootstrapped (\d+)% \([a-z_]+\): ([^\n]*)", txt)
            pct = int(found[-1][0]) if found else 0
            what = found[-1][1].strip() if found else "starting"
            if pct != last:
                last, last_change = pct, time.time()
                if rep: rep(pct)
            if tail:
                strip = lambda l: re.sub(r"[a-z2-7]{56}", "[onion]", re.sub(r"^\w{3} \d\d (\d\d:\d\d:\d\d)\.\d+ ", r"\1 ", l))[:200]
                notable = [strip(l) for l in txt.splitlines() if ("[warn]" in l or "[err]" in l or "Bootstrapped" in l) and "may contain sensitive information" not in l][-5:]
                hsl = [strip(l) for l in hs.splitlines() if self.HS_INTEREST.search(l)][-6:]
                tail(notable + hsl)
            if not self.done.is_set():
                if pct >= 100:
                    if self.use_cache: self._save_cache()      # keep the fresh consensus even if we get killed later
                    self.done.set()
                    if det and self.role == "join":
                        det("Tor is ready (100%). Searching for your friend - this can take up to a minute or two.")
                elif time.time() - self.t_start > 300:
                    self.error = self.error or "tor bootstrap timed out"; self.done.set(); return
                elif det:
                    if re.search(r"(?i)clock (is|may be|appears)|skew|not live yet|consensus is not live", txt):
                        msg = "Tor warns that this device's date/time may be wrong. Turn on automatic time and restart."
                    elif time.time() - last_change > Tor.stall_after:
                        msg = ("Tor is stuck at %d%% (%s). Your network probably blocks Tor, or this device's date/time is wrong. "
                               "Try another Wi-Fi / mobile data / a VPN, or use --bridges / --firewall (see the README)." % (pct, what))
                    else:
                        msg = "Tor %d%%: %s" % (pct, what)
                    if msg != shown: shown = msg; det(msg)
            time.sleep(0.25 if not self.done.is_set() else 1.0)

    def _tor_at_least(self, need):
        try:
            out = subprocess.run([find_tor(), "--version"], capture_output=True, text=True, timeout=10).stdout
            return tuple(int(x) for x in re.search(r"version (\d+)\.(\d+)\.(\d+)", out).groups()) >= need
        except Exception:
            return False

    # ---- host: the onion service. `derived` comes from the pairing code, so the address is known up front.
    def host(self, derived):
        d, seed = self.dir, derived[:32]
        onion, _ = onion_from_seed(seed)
        os.makedirs(d + "/hs/authorized_clients", mode=0o700, exist_ok=True)
        os.chmod(d + "/hs", 0o700)
        secret, public = hs_key_files(seed)
        for name, blob in (("hs_ed25519_secret_key", secret), ("hs_ed25519_public_key", public)):
            fd = os.open(d + "/hs/" + name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f: f.write(blob)
        auth_pub = X25519PrivateKey.from_private_bytes(derived[32:64]).public_key().public_bytes(E, P)
        with open(d + "/hs/authorized_clients/guest.auth", "w") as f:
            f.write("descriptor:x25519:%s\n" % b32(auth_pub))
        sock_path = d + "/s.sock"
        srv = socket.socket(socket.AF_UNIX)
        srv.bind(sock_path); os.chmod(sock_path, 0o600); srv.listen(1); self.srv = srv
        self.role = "host"
        self._start(["SocksPort 0", "HiddenServiceDir %s/hs" % d, "HiddenServicePort %d unix:%s" % (PORT, sock_path)])
        for _ in range(240):                                    # Tor writes the hostname within ~1-2 s
            if os.path.exists(d + "/hs/hostname") or self.error: break
            time.sleep(0.25)
        if self.error or not os.path.exists(d + "/hs/hostname"): raise RuntimeError(self.error or "no onion address")
        with open(d + "/hs/hostname") as f: got = f.read().strip().replace(".onion", "")
        if got != onion: raise RuntimeError("internal error: Tor produced a different onion address than expected")
        def guard():                                            # if Tor fails, stop waiting
            self.done.wait()
            det = getattr(self.ui, "set_detail", None)
            if not self.error and det:
                det("Tor is ready. Your friend can join now (it can take up to a minute after this to become reachable). Keep this window open.")
            if self.error:
                det and det("Tor problem: %s" % self.error)
                try: srv.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                srv.close()
        threading.Thread(target=guard, daemon=True).start()
        try: conn, _ = srv.accept()
        except OSError: raise RuntimeError(self.error or "cancelled")
        srv.close()
        return conn

    # ---- guest: connect to the host's onion address with the code-derived authorization key
    def join(self, onion, key):
        d = self.dir
        os.makedirs(d + "/auth", mode=0o700, exist_ok=True)
        with open(d + "/auth/host.auth_private", "w") as f:
            f.write("%s:descriptor:x25519:%s\n" % (onion, key))
        self.role = "join"
        ext = " ExtendedErrors" if self._tor_at_least((0, 4, 3)) else ""      # lets Tor say WHY a host can't be reached
        self._start(["SocksPort unix:%s/socks.sock%s" % (d, ext), "ClientOnionAuthDir %s/auth" % d])
        det = getattr(self.ui, "set_detail", None)
        deadline, last, tries, t0 = time.time() + 300, None, 0, time.time()
        while time.time() < deadline:                           # Tor queues our request until it is ready
            if self.stopped: raise RuntimeError("cancelled")
            if self.error: raise RuntimeError(self.error)
            try:
                return socks5_unix(d + "/socks.sock", onion + ".onion", PORT)
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.25)                                # tor's socket not up yet
            except Exception as ex:
                last, tries = ex, tries + 1                     # host not published yet - retry quickly
                if det and self.done.is_set():
                    det("Tor is ready. Looking for your friend (try %d, %ds): %s" % (tries, time.time() - t0, ex))
                time.sleep(1.0)
        raise RuntimeError("could not reach your friend after 5 minutes: %s. "
                           "(Each time they restart, they get a NEW code - ask for the newest one.)" % last)



# ======================================================================== pairing code (8 words)
# Word list: BIP-39 English (public domain). 2048 words; the first 4 letters identify each word,
# so typing "abil" is enough for "ability".
WORDS = """
abandon ability able about above absent absorb abstract absurd abuse access accident account accuse
achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust
admit adult advance advice aerobic affair afford afraid again age agent agree ahead aim air airport
aisle alarm album alcohol alert alien all alley allow almost alone alpha already also alter always
amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce
annual another answer antenna antique anxiety any apart apology appear apple approve april arch
arctic area arena argue arm armed armor army around arrange arrest arrive arrow art artefact artist
artwork ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract
auction audit august aunt author auto autumn average avocado avoid awake aware away awesome awful
awkward axis baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely
bargain barrel base basic basket battle beach bean beauty because become beef before begin behave
behind believe below belt bench benefit best betray better between beyond bicycle bid bike bind
biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse
blue blur blush board boat body boil bomb bone bonus book boost border boring borrow boss bottom
bounce box boy bracket brain brand brass brave bread breeze brick bridge brief bright bring brisk
broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet
bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable cactus
cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon capable capital
captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog catch
category cattle caught cause caution cave ceiling celery cement census century cereal certain chair
chalk champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken
chief child chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city
civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip clock
clog close cloth cloud clown club clump cluster clutch coach coast coconut code coffee coil coin
collect color column combine come comfort comic common company concert conduct confirm congress
connect consider control convince cook cool copper copy coral core corn correct cost cotton couch
country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy
cream credit creek crew cricket crime crisp critic crop cross crouch crowd crucial cruel cruise
crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion
custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris
decade december decide decline decorate decrease deer defense define defy degree delay deliver
demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design
desk despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet
differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss
disorder display distance divert divide divorce dizzy doctor document dog doll dolphin domain donate
donkey donor door dose double dove draft dragon drama drastic draw dream dress drift drill drink
drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn
earth easily east easy echo ecology economy edge edit educate effort egg eight either elbow elder
electric elegant element elephant elevator elite else embark embody embrace emerge emotion employ
empower empty enable enact end endless endorse enemy energy enforce engage engine enhance enjoy
enlist enough enrich enroll ensure enter entire entry envelope episode equal equip era erase erode
erosion error erupt escape essay essence estate eternal ethics evidence evil evoke evolve exact
example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit
exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade
faint faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue
fault favorite feature february federal fee feed feel female fence festival fetch fever few fiber
fiction field figure file film filter final find fine finger finish fire firm first fiscal fish fit
fitness fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly
foam focus fog foil fold follow food foot force forest forget fork fortune forum forward fossil
foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel
fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic
garment gas gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift
giggle ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow
glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape
grass gravity great green grid grief grit grocery group grow grunt guard guess guide guilt guitar
gun gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard
head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip hire
history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse hospital host
hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband hybrid
ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose
improve impulse inch include income increase index indicate indoor industry infant inflict inform
inhale inherit initial inject injury inmate inner innocent input inquiry insane insect inside
inspire install intact interest into invest invite involve iron island isolate issue item ivory
jacket jaguar jar jazz jealous jeans jelly jewel job join joke journey joy judge juice jump jungle
junior junk just kangaroo keen keep ketchup key kick kid kidney kind kingdom kiss kit kitchen kite
kitten kiwi knee knife knock know lab label labor ladder lady lake lamp language laptop large later
latin laugh laundry lava law lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal
legend leisure lemon lend length lens leopard lesson letter level liar liberty library license life
lift light like limb limit link lion liquid list little live lizard load loan lobster local lock
logic lonely long loop lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics
machine mad magic magnet maid mail main major make mammal man manage mandate mango mansion manual
maple marble march margin marine market marriage mask mass master match material math matrix matter
maximum maze meadow mean measure meat mechanic medal media melody melt member memory mention menu
mercy merge merit merry mesh message metal method middle midnight milk million mimic mind minimum
minor minute miracle mirror misery miss mistake mix mixed mixture mobile model modify mom moment
monitor monkey monster month moon moral more morning mosquito mother motion motor mountain mouse
move movie much muffin mule multiply muscle museum mushroom music must mutual myself mystery myth
naive name napkin narrow nasty nation nature near neck need negative neglect neither nephew nerve
nest net network neutral never news next nice night noble noise nominee noodle normal north nose
notable note nothing notice novel now nuclear number nurse nut oak obey object oblige obscure
observe obtain obvious occur ocean october odor off offer office often oil okay old olive olympic
omit once one onion online only open opera opinion oppose option orange orbit orchard order ordinary
organ orient original orphan ostrich other outdoor outer output outside oval oven over own owner
oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper parade parent
park parrot party pass patch path patient patrol pattern pause pave payment peace peanut pear
peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase
physical piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place
planet plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond
pony pool popular portion position possible post potato pottery poverty powder power practice praise
predict prefer prepare present pretty prevent price pride primary print priority prison private
prize problem process produce profit program project promote proof property prosper protect proud
provide public pudding pull pulp pulse pumpkin punch pupil puppy purchase purity purpose purse push
put puzzle pyramid quality quantum quarter question quick quit quiz quote rabbit raccoon race rack
radar radio rail rain raise rally ramp ranch random range rapid rare rate rather raven raw razor
ready real reason rebel rebuild recall receive recipe record recycle reduce reflect reform refuse
region regret regular reject relax release relief rely remain remember remind remove render renew
rent reopen repair repeat replace report require rescue resemble resist resource response result
retire retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle
right rigid ring riot ripple risk ritual rival river road roast robot robust rocket romance roof
rookie room rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle
sadness safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save
say scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script
scrub sea search season seat second secret section security seed seek segment select sell seminar
senior sense sentence series service session settle setup seven shadow shaft shallow share shed
shell sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug
shuffle shy sibling sick side siege sight sign silent silk silly silver similar simple since sing
siren sister situate six size skate sketch ski skill skin skirt skull slab slam sleep slender slice
slide slight slim slogan slot slow slush small smart smile smoke smooth snack snake snap sniff snow
soap soccer social sock soda soft solar soldier solid solution solve someone song soon sorry sort
soul sound soup source south space spare spatial spawn speak special speed spell spend sphere spice
spider spike spin spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze
squirrel stable stadium staff stage stairs stamp stand start state stay steak steel stem step stereo
stick still sting stock stomach stone stool story stove strategy street strike strong struggle
student stuff stumble style subject submit subway success such sudden suffer sugar suggest suit
summer sun sunny sunset super supply supreme sure surface surge surprise surround survey suspect
sustain swallow swamp swap swarm swear sweet swift swim swing switch sword symbol symptom syrup
system table tackle tag tail talent talk tank tape target task taste tattoo taxi teach team tell ten
tenant tennis tent term test text thank that theme then theory there they thing this thought three
thrive throw thumb thunder ticket tide tiger tilt timber time tiny tip tired tissue title toast
tobacco today toddler toe together toilet token tomato tomorrow tone tongue tonight tool tooth top
topic topple torch tornado tortoise toss total tourist toward tower town toy track trade traffic
tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim trip
trophy trouble truck true truly trumpet trust truth try tube tuition tumble tuna tunnel turkey turn
turtle twelve twenty twice twin twist two type typical ugly umbrella unable unaware uncle uncover
under undo unfair unfold unhappy uniform unique unit universe unknown unlock until unusual unveil
update upgrade uphold upon upper upset urban urge usage use used useful useless usual utility vacant
vacuum vague valid valley valve van vanish vapor various vast vault vehicle velvet vendor venture
venue verb verify version very vessel veteran viable vibrant vicious victory video view village
vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote
voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave way
wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat wheel
when where whip whisper wide width wife wild will win window wine wing wink winner winter wire
wisdom wise wish witness wolf woman wonder wood wool word work world worry worth wrap wreck wrestle
wrist write wrong yard year yellow you young youth zebra zero zone zoo
""".split()
WORD_INDEX = {w: i for i, w in enumerate(WORDS)}
PREFIX = {w[:4]: w for w in WORDS}
CODE_WORDS = 8                         # 7 random words (77 bits) + 1 checksum word

def _word_bytes(idx):
    return bytes(x for i in idx for x in (i >> 8, i & 255))

def _checksum(idx7):
    h = hashlib.sha256(b"torchat-code-v1" + _word_bytes(idx7)).digest()
    return ((h[0] << 8 | h[1]) >> 5) & 0x7FF

def new_code():
    idx = [secrets.randbelow(2048) for _ in range(7)]
    return idx + [_checksum(idx)]

def code_words(idx):
    return [WORDS[i] for i in idx]

def parse_code(text):
    """Accepts any case, spaces/dashes/commas, and 4-letter abbreviations. Raises ValueError with a friendly reason."""
    toks = re.findall(r"[a-zA-Z]+", text.lower())
    if len(toks) != CODE_WORDS:
        raise ValueError("The code has %d words (you entered %d)." % (CODE_WORDS, len(toks)))
    idx = []
    for n, t in enumerate(toks, 1):
        w = t if t in WORD_INDEX else None
        if w is None and len(t) >= 4 and PREFIX.get(t[:4], "").startswith(t): w = PREFIX[t[:4]]
        if w is None:
            raise ValueError("Word %d (\"%s\") is not in the word list - check the spelling." % (n, t[:20]))
        idx.append(WORD_INDEX[w])
    if _checksum(idx[:7]) != idx[7]:
        raise ValueError("The code does not check out - a word is wrong or in the wrong order.")
    return idx

def derive(idx):
    """Stretch the 7 random words into 128 bytes: [0:32] onion seed, [32:64] client-auth key, [64:96] handshake secret."""
    return Scrypt(salt=b"torchat-pairing-v1", length=128, n=2 ** 16, r=8, p=1).derive(_word_bytes(idx[:7]))



# ======================================================================== engine (no UI code in here)
def default_save_dir():
    home = os.path.expanduser("~")
    for base, sub in (("storage/downloads", "torchat"), ("Downloads", "torchat")):
        if os.path.isdir(os.path.join(home, base)): return os.path.join(home, base, sub)
    return os.path.join(home, "torchat-received")


class Messenger:
    """Everything except drawing. A UI reads .stage/.progress/.detail/.tail/.code_words/.sas and the event
       queue .q (dicts with kind = stage | sys | in | out | file_in | file_out), and calls the methods below."""
    def __init__(self, passphrase=""):
        self.q, self.n_events = queue.Queue(), 0
        self.stage, self.error_text = "idle", ""
        self.sas, self.code_words, self.psk = None, None, ""
        self.progress, self.detail, self.tail = 0, "", []
        self.passphrase = passphrase
        self.chat, self.tor = None, None
        self.files, self.transfers = {}, {}
        self.recv_total = self.sent_total = 0
        self.verify_evt, self.verify_ok = threading.Event(), False
        self.upload_lock = threading.Lock()
        sweep_stale()
        self.recvdir = private_tmp()
        with open(os.path.join(self.recvdir, "pid"), "w") as f: f.write(str(os.getpid()))
        atexit.register(self.wipe)

    # ---- plumbing used by the Tor wrapper and the Chat protocol
    def emit(self, **kw):
        self.n_events += 1; kw["ts"] = time.time(); self.q.put(kw)
    def show(self, s): self.emit(kind="sys", text=str(s).strip())
    def set_progress(self, pct): self.progress = pct
    def set_detail(self, text): self.detail = text
    def set_tail(self, lines): self.tail = list(lines)
    def set_stage(self, stage):
        self.stage = stage; self.emit(kind="stage", stage=stage)

    def wipe(self):
        if self.tor: self.tor.stop()
        wipe_dir(self.recvdir)

    # ---- starting a chat
    def start_host(self):
        if self.stage != "idle": return
        self.set_stage("starting")
        threading.Thread(target=self._run_host, daemon=True).start()

    def _run_host(self):
        try:
            idx = new_code(); derived = derive(idx)              # ~0.3 s
            self.code_words, self.psk = code_words(idx), derived[64:96].hex()
            self.set_stage("invite")                             # the code is shown at once; Tor starts now
            self.tor = Tor(self)
            sock = self.tor.host(derived)
            self._connected(sock, "host")
        except Exception as ex:
            self._fail(ex)

    def start_join(self, text):
        """Raises ValueError(friendly message) if the code is mistyped - before anything starts."""
        idx = parse_code(text)
        if self.stage != "idle": return
        self.set_stage("starting")
        threading.Thread(target=self._run_join, args=(idx,), daemon=True).start()

    def _run_join(self, idx):
        try:
            derived = derive(idx)
            onion, _ = onion_from_seed(derived[:32])
            self.psk = derived[64:96].hex()
            self.set_stage("connecting")
            self.tor = Tor(self)
            sock = self.tor.join(onion, b32(derived[32:64]))
            self._connected(sock, "join")
        except Exception as ex:
            self._fail(ex)

    def connect_socket(self, sock, mode, psk=""):
        """Use an already-open connection (tests / future transports)."""
        self.psk = psk
        threading.Thread(target=self._run_socket, args=(sock, mode), daemon=True).start()

    def _run_socket(self, sock, mode):
        try: self._connected(sock, mode)
        except Exception as ex: self._fail(ex)

    def _connected(self, sock, mode):
        self.detail = "Connected to your friend through Tor. Setting up encryption..."
        sock.settimeout(180)
        ratchet, sas = handshake(sock, mode, self.psk + self.passphrase)
        sock.settimeout(None)
        self.sas = sas
        self.set_stage("verify")
        self.verify_evt.wait(600)
        if not self.verify_ok:
            sock.close(); self.emit(kind="sys", text="Closed: the safety code was not confirmed."); self.set_stage("closed"); return
        self.chat = Chat(self, sock, ratchet, mode)
        self.set_stage("chat")
        self.chat.start()

    def _fail(self, ex):
        if self.stage == "closed": return
        self.error_text = str(ex) or type(ex).__name__
        self.emit(kind="sys", text="Error: %s" % self.error_text)
        self.set_stage("error")

    def confirm(self, ok):
        if self.stage != "verify": return
        self.verify_ok = bool(ok); self.verify_evt.set()

    # ---- chatting
    @property
    def ready(self): return self.stage == "chat" and bool(self.chat and self.chat.ready)

    def send_text(self, text):
        if not self.ready: raise RuntimeError("Not connected yet.")
        self.chat.send_text(text)

    def send_file(self, path):
        if not self.ready: raise RuntimeError("Not connected yet.")
        if not self.upload_lock.acquire(False): raise RuntimeError("Another file is still being sent.")
        try:
            with open(path, "rb") as f:
                st = os.fstat(f.fileno())
                if not stat.S_ISREG(st.st_mode): raise ValueError("That is not a regular file.")
                self.chat.send_upload(os.path.basename(path), st.st_size, f)
        finally:
            self.upload_lock.release()

    def save_file(self, fid, dest_dir=None):
        """Copy a received file out of the private temp folder. Never overwrites; returns the new path."""
        f = self.files.get(fid)
        if not f: raise KeyError("unknown file")
        dest_dir = dest_dir or default_save_dir()
        os.makedirs(dest_dir, mode=0o700, exist_ok=True)
        base, ext = os.path.splitext(safe_name(f["name"]))
        n = 0
        while True:
            name = base + ("" if n == 0 else " (%d)" % n) + ext
            path = os.path.join(dest_dir, name)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                break
            except FileExistsError:
                n += 1
        with os.fdopen(fd, "wb") as out, open(f["path"], "rb") as src: shutil.copyfileobj(src, out)
        return path

    def end(self):
        try:
            if self.chat:
                try: self.chat.s.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                self.chat.s.close()
        except OSError: pass
        self.stage = "closed"; self.wipe()



# ======================================================================== text interface
class Tui:
    def __init__(self, m):
        self.m, self.lock, self.fids, self.chatting = m, threading.Lock(), [], False
        try: import readline  # noqa: F401  (line editing + history where available)
        except ImportError: pass

    def say(self, text):
        with self.lock:
            print("\r\033[K" + text, flush=True)
            if self.chatting: print("you> ", end="", flush=True)

    def pump(self):
        m = self.m
        while True:
            try: e = m.q.get(timeout=0.3)
            except queue.Empty: continue
            k = e["kind"]
            if k == "sys": self.say("* " + e["text"])
            elif k == "in": self.say("friend> " + e["text"])
            elif k == "file_in":
                self.fids.append(e["fid"])
                self.say("[file %d] received: %s (%s)%s - type /save %d to keep it" % (
                    len(self.fids), e["name"], human(e["size"]),
                    "  !! program-type file: only open it if you fully trust your friend" if e.get("warn") else "", len(self.fids)))
            elif k == "file_out":
                self.say("[sent] %s (%s)%s" % (e["name"], human(e["size"]),
                         " - photo details removed" if e.get("scrubbed") else
                         ("  (note: hidden author/location details are NOT removed from this type of file)" if not e.get("image") else "")))
            elif k == "stage" and e["stage"] in ("closed", "error") and self.chatting:
                self.say("[the chat has ended]"); _thread.interrupt_main()

    def show_code(self):
        w = self.m.code_words
        print("\n  YOUR PAIRING CODE - tell these 8 words to ONE friend (call, message, in person):\n")
        print("      " + "   ".join("%d. %s" % (i + 1, x) for i, x in enumerate(w[:4])))
        print("      " + "   ".join("%d. %s" % (i + 5, x) for i, x in enumerate(w[4:])))
        print("\n  They choose 'Join a chat' and type the words. The code works once, and only while")
        print("  this screen stays open.\n")

    def run(self):
        m = self.m
        print("\n  torchat - private chat with anyone in the world")
        print("  end-to-end encrypted, no servers, nothing stored\n")
        threading.Thread(target=self.pump, daemon=True).start()
        while True:
            print("  1) Start a chat   (you get a code to share)")
            print("  2) Join a chat    (you type a code your friend gave you)")
            print("  3) Quit")
            c = input("Choose 1, 2 or 3: ").strip()
            if c == "1":
                m.start_host(); break
            if c == "2":
                done = False
                while not done:
                    text = input("Type the 8-word code (or press Enter to go back): ")
                    if not text.strip(): break
                    try: m.start_join(text); done = True
                    except ValueError as ex: print("  " + str(ex))
                if done: break
            elif c == "3": return
        self.wait_for_connection()
        if m.stage == "verify": self.verify()
        while m.stage in ("verify", "starting"): time.sleep(0.2)
        if m.stage == "chat": self.chat_loop()
        elif m.stage == "error": print("\nCould not connect: %s" % m.error_text)

    def wait_for_connection(self):
        m, shown, last, t0, ping = self.m, False, "", time.time(), time.time()
        while m.stage in ("starting", "invite", "connecting"):
            if m.stage == "invite" and m.code_words and not shown: self.show_code(); shown = True
            line = ("Tor %d%% - %s" % (m.progress, m.detail)) if m.detail else ("Tor %d%%" % m.progress)
            if line != last: self.say(line); last = line; ping = time.time()
            elif time.time() - ping > 30:
                self.say("  ...still waiting (%d s). Press Ctrl+C to cancel." % (time.time() - t0)); ping = time.time()
            time.sleep(0.3)

    def verify(self):
        m = self.m
        print("\n  SAFETY CODE:  %s\n" % m.sas)
        print("  Ask your friend (by call or in person - NOT in this chat) to read you THEIR safety code.")
        ok = input("  Is it exactly the same? Type yes or no: ").strip().lower() in ("y", "yes")
        m.confirm(ok)
        if not ok: print("  Stopped. Someone may be interfering - do not chat. Start again with a new code.")

    def chat_loop(self):
        m = self.m
        print("\n  Connected and verified. Just type to chat. Commands: /send <file>  /save <n> [folder]  /files  /help  /quit\n")
        self.chatting = True
        while m.stage == "chat":
            try: line = input("you> ").strip()
            except (EOFError, KeyboardInterrupt): break
            if m.stage != "chat": break
            if not line: continue
            try:
                if line.startswith("/"): self.command(line)
                else: m.send_text(line)
            except (RuntimeError, ValueError, OSError, KeyError) as ex:
                self.say("* " + str(ex))
        self.chatting = False

    def command(self, line):
        import shlex
        m = self.m
        try: parts = shlex.split(line)
        except ValueError: parts = line.split()
        cmd, args = parts[0].lower(), parts[1:]
        if cmd == "/quit": raise KeyboardInterrupt
        if cmd == "/help":
            self.say("  /send <file>        send an image or document\n  /files              list received files\n"
                     "  /save <n> [folder]  keep received file n (default folder: %s)\n  /quit               leave and wipe everything" % default_save_dir())
        elif cmd == "/files":
            self.say("\n".join("  [%d] %s (%s)" % (i + 1, m.files[f]["name"], human(m.files[f]["size"])) for i, f in enumerate(self.fids) if f in m.files) or "  no files yet")
        elif cmd == "/save":
            if not args or not args[0].isdigit() or not (1 <= int(args[0]) <= len(self.fids)): raise ValueError("usage: /save <number> [folder]")
            path = m.save_file(self.fids[int(args[0]) - 1], os.path.expanduser(args[1]) if len(args) > 1 else None)
            self.say("  saved to %s" % path)
        elif cmd == "/send":
            if not args: raise ValueError("usage: /send <file>")
            path = os.path.expanduser(" ".join(args))
            def work():
                try: m.send_file(path)
                except Exception as ex: self.say("* could not send: %s" % ex)
            self.say("  sending %s ..." % os.path.basename(path))
            threading.Thread(target=work, daemon=True).start()
        else:
            raise ValueError("unknown command - type /help")



# ======================================================================== desktop window (tkinter)
THEMES = {
    "dark": dict(bg="#0f1115", surface="#171a21", surface2="#222631", border="#2e3340", text="#e8eaed", muted="#9aa1ad",
                 accent="#6644ee", accent_hover="#5836dd", accent_text="#ffffff", accent_soft="#29234d", accent_fg="#9d85ff",
                 me="#6644ee", me_text="#ffffff", me_sub="#f1eeff", peer="#222631", peer_text="#e8eaed", peer_sub="#a9afba",
                 ok="#34c77b", warn="#f5a524", danger="#f05252", danger_hover="#dc3c3c", danger_soft="#3a1d22"),
    "light": dict(bg="#f4f5f8", surface="#ffffff", surface2="#eceef3", border="#d9dce4", text="#14161a", muted="#5d6470",
                  accent="#5b3df0", accent_hover="#4a2fd6", accent_text="#ffffff", accent_soft="#ece8ff", accent_fg="#5b3df0",
                  me="#5b3df0", me_text="#ffffff", me_sub="#f1eeff", peer="#ffffff", peer_text="#14161a", peer_sub="#5d6470",
                  ok="#15803d", warn="#b45309", danger="#d92d2d", danger_hover="#b91c1c", danger_soft="#fde8e8"),
}

GUI_TIPS = ("Tips: ask your friend for their NEWEST code (every restart makes a new one), keep both windows open, "
            "check the date and time on both devices, and try another network if yours blocks Tor (see the README for bridges).")


def _rrect(cv, x1, y1, x2, y2, r, **kw):
    """Rounded rectangle on a tk Canvas (smoothed polygon)."""
    r = max(0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    pts = (x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
           x1, y2, x1, y2 - r, x1, y1 + r, x1, y1)
    return cv.create_polygon(pts, smooth=True, **kw)


def _widgets(tk):
    """Canvas-drawn widgets (rounded, themeable). Built lazily so the text screen never needs tkinter."""

    class Shape(tk.Canvas):
        minw = 40
        def __init__(self, gui, parent, bg="bg", **kw):
            super().__init__(parent, highlightthickness=0, bd=0, width=self.minw, height=10, **kw)
            self.gui, self.bgtok = gui, bg
            gui.shapes.append(self)
            self.bind("<Configure>", lambda e: self._paint())
        def measure(self): return None, 10
        def size(self):
            w, h = self.winfo_width(), self.winfo_height()
            return (w if w > 1 else int(self["width"])), (h if h > 1 else int(self["height"]))
        def refresh(self):
            w, h = self.measure()
            self.configure(bg=self.gui.c[self.bgtok], width=w or self.minw, height=h)
            self._paint()
        def _paint(self):
            self.delete("d"); self.paint(*self.size())
        def paint(self, W, H): pass

    class Button(Shape):
        """Rounded button. kind: primary | secondary | ghost | danger-ghost | link | chip (static)."""
        def __init__(self, gui, parent, text, command=None, kind="primary", font="bold", bg="bg",
                     padx=18, pady=9, fill=False, radius=10, static=False):
            self.text, self.command, self.kind, self.fontkey = text, command, kind, font
            self.padx, self.pady, self.fill, self.radius = padx, pady, fill, radius
            self.enabled, self.hover, self.focus = True, False, False
            super().__init__(gui, parent, bg=bg, takefocus=0 if static else 1, cursor="" if static else "hand2")
            if not static:
                self.bind("<Enter>", lambda e: self._set(hover=True)); self.bind("<Leave>", lambda e: self._set(hover=False))
                self.bind("<ButtonRelease-1>", lambda e: self.hover and self.invoke())
                for k in ("<Return>", "<KP_Enter>", "<space>"): self.bind(k, lambda e: self.invoke())
                self.bind("<FocusIn>", lambda e: self._set(focus=True)); self.bind("<FocusOut>", lambda e: self._set(focus=False))
            self.refresh()
        def _set(self, **kw):
            for k, v in kw.items(): setattr(self, k, v)
            self._paint()
        def set_text(self, text): self.text = text; self.refresh()
        def set_enabled(self, on):
            self.enabled = bool(on); self.configure(cursor="hand2" if on else ""); self._paint()
        def invoke(self):
            if self.enabled and self.command: self.command()
        def measure(self):
            f = self.gui.f[self.fontkey]
            return (None if self.fill else f.measure(self.text) + 2 * self.padx), f.metrics("linespace") + 2 * self.pady
        def paint(self, W, H):
            c, k = self.gui.c, self.kind; under = c[self.bgtok]
            fill, hov, fg = {"primary": (c["accent"], c["accent_hover"], c["accent_text"]),
                             "secondary": (c["surface2"], c["border"], c["text"]),
                             "ghost": (under, c["surface2"], c["text"]),
                             "danger-ghost": (under, c["danger_soft"], c["danger"]),
                             "link": (under, under, c["accent_fg"]),
                             "chip": (c["surface2"], c["surface2"], c["muted"])}[k]
            if not self.enabled:
                fill = hov = c["surface2"] if k in ("primary", "secondary") else under; fg = c["muted"]
            body = hov if self.hover and self.enabled else fill
            _rrect(self, 1, 1, W - 2, H - 2, self.radius, fill=body, outline=c["accent_fg"] if self.focus else body,
                   width=2 if self.focus else 1, tags="d")
            self.create_text(W / 2, H / 2, text=self.text, fill=fg, font=self.gui.f[self.fontkey], tags="d")

    class Card(Shape):
        """Big clickable choice card: icon, title, one-line description, chevron."""
        def __init__(self, gui, parent, icon, title, sub, command):
            self.icon, self.title, self.sub, self.command = icon, title, sub, command
            self.hover, self.focus, self.h = False, False, 90
            super().__init__(gui, parent, takefocus=1, cursor="hand2")
            self.bind("<Enter>", lambda e: self._set(True, None)); self.bind("<Leave>", lambda e: self._set(False, None))
            self.bind("<FocusIn>", lambda e: self._set(None, True)); self.bind("<FocusOut>", lambda e: self._set(None, False))
            self.bind("<ButtonRelease-1>", lambda e: self.hover and command())
            for k in ("<Return>", "<KP_Enter>", "<space>"): self.bind(k, lambda e: command())
            self.refresh()
        def _set(self, hover, focus):
            if hover is not None: self.hover = hover
            if focus is not None: self.focus = focus
            self._paint()
        def measure(self): return None, self.h
        def paint(self, W, H):
            c, f, pad = self.gui.c, self.gui.f, 18
            ic = f["h2"].metrics("linespace") + 20
            _rrect(self, 1, 1, W - 2, H - 2, 16, fill=c["surface2"] if self.hover else c["surface"],
                   outline=c["accent_fg"] if (self.hover or self.focus) else c["border"], width=2 if self.focus else 1, tags="d")
            self.create_oval(pad, pad, pad + ic, pad + ic, fill=c["accent_soft"], outline=c["accent_soft"], tags="d")
            self.create_text(pad + ic / 2, pad + ic / 2, text=self.icon, fill=c["accent_fg"], font=f["h2"], tags="d")
            tx = pad + ic + 16
            t = self.create_text(tx, pad + 2, text=self.title, anchor="nw", fill=c["text"], font=f["h2"], tags="d")
            s = self.create_text(tx, self.bbox(t)[3] + 4, text=self.sub, anchor="nw", width=max(80, W - tx - pad - 30),
                                 fill=c["muted"], font=f["normal"], tags="d")
            self.create_text(W - pad, H / 2, text="›", anchor="e", fill=c["muted"], font=f["h1"], tags="d")
            need = max(self.bbox(s)[3], pad + ic) + pad
            if need != self.h: self.h = need; self.configure(height=need)

    class Field(Shape):
        """Rounded text input (an Entry inside a drawn box) with a focus ring."""
        def __init__(self, gui, parent, font="normal", show="", bg="bg", padx=14, pady=10):
            self.fontkey, self.padx, self.pady, self.focus = font, padx, pady, False
            super().__init__(gui, parent, bg=bg)
            self.entry = gui.reg(tk.Entry(self, relief="flat", bd=0, highlightthickness=0, font=gui.f[font], show=show),
                                 bg="surface2", fg="text", insertbackground="text", disabledbackground="surface2",
                                 disabledforeground="muted", selectbackground="accent", selectforeground="accent_text")
            self.win = self.create_window(padx, 0, window=self.entry, anchor="w")
            self.entry.bind("<FocusIn>", lambda e: self._set(True), add="+"); self.entry.bind("<FocusOut>", lambda e: self._set(False), add="+")
            self.bind("<Button-1>", lambda e: self.entry.focus_set())
            self.refresh()
        def _set(self, focus): self.focus = focus; self._paint()
        def measure(self): return None, self.gui.f[self.fontkey].metrics("linespace") + 2 * self.pady + 4
        def paint(self, W, H):
            c = self.gui.c
            _rrect(self, 1, 1, W - 2, H - 2, 12, fill=c["surface2"], outline=c["accent_fg"] if self.focus else c["border"],
                   width=2 if self.focus else 1, tags="d")
            self.coords(self.win, self.padx, H / 2); self.itemconfigure(self.win, width=max(20, W - 2 * self.padx))

    class Chip(Shape):
        """One pairing-code word (with its number) or one safety-code group."""
        def __init__(self, gui, parent, num=None, word=""):
            self.num, self.word = num, word
            super().__init__(gui, parent); self.refresh()
        def set(self, word): self.word = word; self._paint()
        def measure(self): return None, self.gui.f["monobig"].metrics("linespace") + 20
        def paint(self, W, H):
            c, f = self.gui.c, self.gui.f
            _rrect(self, 1, 1, W - 2, H - 2, 12, fill=c["surface2"], outline=c["border"], tags="d")
            if self.num is None:
                self.create_text(W / 2, H / 2, text=self.word, fill=c["text"], font=f["monobig"], tags="d"); return
            self.create_text(14, H / 2, text=str(self.num), anchor="w", fill=c["muted"], font=f["small"], tags="d")
            self.create_text(14 + f["small"].measure("8") + 10, H / 2, text=self.word, anchor="w", fill=c["text"], font=f["monobig"], tags="d")

    class Badge(Shape):
        """Round (or rounded-square) icon: the logo, the chat avatar, the error mark."""
        def __init__(self, gui, parent, glyph, fill="accent_soft", fg="accent_fg", square=False, bg="bg", font="h2"):
            self.glyph, self.filltok, self.fgtok, self.square, self.fontkey = glyph, fill, fg, square, font
            super().__init__(gui, parent, bg=bg); self.refresh()
        def measure(self):
            s = self.gui.f[self.fontkey].metrics("linespace") + 16
            return s, s
        def paint(self, W, H):
            c = self.gui.c
            if self.square: _rrect(self, 0, 0, W - 1, H - 1, 10, fill=c[self.filltok], outline=c[self.filltok], tags="d")
            else: self.create_oval(0, 0, W - 1, H - 1, fill=c[self.filltok], outline=c[self.filltok], tags="d")
            self.create_text(W / 2, H / 2, text=self.glyph, fill=c[self.fgtok], font=self.gui.f[self.fontkey], tags="d")

    class Bubble(Shape):
        """A chat bubble: one or more (text, font, colour) lines, wrapped to the chat width. Right-click copies."""
        def __init__(self, gui, parent, lines, fill, copy=None):
            self.lines, self.filltok, self.copy_text = lines, fill, copy
            super().__init__(gui, parent)
            for b in ("<Button-3>", "<Button-2>"): self.bind(b, self.menu)
            self.refresh()
        def refresh(self): self.configure(bg=self.gui.c[self.bgtok]); self._paint()
        def _paint(self):
            c, f, px, py = self.gui.c, self.gui.f, 14, 9
            self.delete("d"); y, w = py, 0
            for text, fk, tok in self.lines:
                t = self.create_text(px, y, text=text, anchor="nw", width=self.gui.wrap, fill=c[tok], font=f[fk], tags="d")
                x1, y1, x2, y2 = self.bbox(t); w = max(w, x2 - px); y = y2 + 3
            W, H = w + 2 * px, y - 3 + py
            self.tag_lower(_rrect(self, 0, 0, W - 1, H - 1, 14, fill=c[self.filltok], outline=c[self.filltok], tags="d"))
            if (int(self["width"]), int(self["height"])) != (W, H): self.configure(width=W, height=H)
        def menu(self, e):
            if not self.copy_text: return
            c = self.gui.c
            m = tk.Menu(self, tearoff=0, bg=c["surface"], fg=c["text"], activebackground=c["accent"],
                        activeforeground=c["accent_text"], bd=0, font=self.gui.f["normal"])
            m.add_command(label="Copy text", command=lambda: (self.clipboard_clear(), self.clipboard_append(self.copy_text)))
            m.tk_popup(e.x_root, e.y_root)

    return Button, Card, Field, Chip, Badge, Bubble


class Gui:
    """Modern, keyboard-friendly window in plain tkinter (no extra packages). Dark and light themes.
       No images are decoded or rendered (fewer ways to be attacked); received files are saved on request
       and opened by YOU with your own programs."""
    FONTS = ("Inter", "Segoe UI", "SF Pro Text", "Helvetica Neue", "Ubuntu", "Cantarell", "Noto Sans", "DejaVu Sans")
    MONO = ("JetBrains Mono", "Cascadia Mono", "SF Mono", "Menlo", "Consolas", "Ubuntu Mono", "DejaVu Sans Mono")

    def __init__(self):
        import tkinter as tk
        from tkinter import ttk, messagebox, filedialog, font as tkfont
        self.tk, self.ttk, self.mb, self.fd = tk, ttk, messagebox, filedialog
        self.Button, self.Card, self.Field, self.Chip, self.Badge, self.Bubble = _widgets(tk)
        self.m, self.role = Messenger(), "host"
        self.root = tk.Tk()
        self.root.title("torchat"); self.root.geometry("800x780"); self.root.minsize(640, 620)
        self.theme, self.c, self.scale = "dark", THEMES["dark"], 1.0
        self.themed, self.shapes, self.bubbles, self.sys_labels = {}, [], [], []
        fams = set(tkfont.families())
        fam = next((x for x in self.FONTS if x in fams), tkfont.nametofont("TkDefaultFont").cget("family"))
        mono = next((x for x in self.MONO if x in fams), tkfont.nametofont("TkFixedFont").cget("family"))
        self.f = {k: tkfont.Font(family=mono if k.startswith("mono") else fam)
                  for k in ("small", "normal", "bold", "h2", "h1", "mono", "monobig")}
        self.apply_fonts()
        self.root.option_add("*Font", self.f["normal"])
        self.style = ttk.Style(self.root)
        try: self.style.theme_use("clam")
        except tk.TclError: pass
        self.root.grid_rowconfigure(0, weight=1); self.root.grid_columnconfigure(0, weight=1)
        self.frames, self.cur, self.stage_since, self.tail_shown = {}, "", time.time(), None
        self.last_sys, self.wrap, self.ready_shown, self.hint_shown, self._rewrap_job = "", 420, None, None, None
        self.sendq = queue.Queue()
        threading.Thread(target=self._sender, daemon=True).start()
        self._home(); self._join(); self._wait(); self._verify(); self._chat(); self._error()
        self.apply_theme()
        self.show("home")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        for key, d in (("<Control-plus>", 0.1), ("<Control-equal>", 0.1), ("<Control-minus>", -0.1)):
            self.root.bind(key, lambda e, d=d: self.zoom(d))
        self.root.bind("<Control-o>", lambda e: self.cur == "chat" and self.attach())
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"): self.root.bind_all(seq, self._wheel, add="+")
        self.root.after(100, self.pump)

    # ---- theming + building blocks
    def reg(self, w, **roles):
        self.themed[w] = roles; self._color(w, roles); return w

    def recolor(self, w, **roles):
        self.themed.setdefault(w, {}).update(roles); self._color(w, roles)

    def _color(self, w, roles):
        try: w.configure(**{k: self.c[v] for k, v in roles.items()})
        except self.tk.TclError: pass

    def F(self, parent, bg="bg", **kw):
        return self.reg(self.tk.Frame(parent, bd=0, highlightthickness=0, **kw), bg=bg)

    def L(self, parent, text="", font="normal", fg="text", bg="bg", wrap=0, justify="left", anchor="w"):
        return self.reg(self.tk.Label(parent, text=text, font=self.f[font], wraplength=wrap, justify=justify,
                                      anchor=anchor, bd=0, padx=0, pady=0), fg=fg, bg=bg)

    def apply_fonts(self):
        s = 11 * self.scale
        for k, mult, weight in (("small", .87, "normal"), ("normal", 1, "normal"), ("bold", 1, "bold"), ("h2", 1.25, "bold"),
                                ("h1", 2.0, "bold"), ("mono", 1, "normal"), ("monobig", 1.3, "bold")):
            self.f[k].configure(size=max(7, round(s * mult)), weight=weight)

    def apply_theme(self):
        c = self.c = THEMES[self.theme]
        self.root.configure(bg=c["bg"])
        for w in [w for w in self.themed if not w.winfo_exists()]: del self.themed[w]
        for w, roles in self.themed.items(): self._color(w, roles)
        self.shapes = [s for s in self.shapes if s.winfo_exists()]
        for s in self.shapes: s.refresh()
        st = self.style
        st.configure("TC.Horizontal.TProgressbar", background=c["accent"], troughcolor=c["surface2"], bordercolor=c["surface2"],
                     lightcolor=c["accent"], darkcolor=c["accent"], thickness=8)
        st.configure("TC.Vertical.TScrollbar", background=c["surface2"], troughcolor=c["bg"], bordercolor=c["bg"],
                     arrowcolor=c["muted"], lightcolor=c["surface2"], darkcolor=c["surface2"], gripcount=0)
        st.map("TC.Vertical.TScrollbar", background=[("active", c["border"])])
        self.theme_btn.set_text("☀" if self.theme == "dark" else "☾")

    def toggle_theme(self):
        self.theme = "light" if self.theme == "dark" else "dark"; self.apply_theme()

    def zoom(self, d):
        self.scale = min(1.8, max(0.8, self.scale + d)); self.apply_fonts(); self.apply_theme()

    def screen(self, name, maxw=600):
        scr = self.F(self.root); scr.grid(row=0, column=0, sticky="nsew"); self.frames[name] = scr
        if not maxw: return scr
        col = self.F(scr)
        def fit(e):
            w = max(200, min(maxw, e.width - 48)); col.place(x=(e.width - w) // 2, y=0, width=w, height=e.height)
        scr.bind("<Configure>", fit)
        return col

    def show(self, name):
        self.frames[name].tkraise(); self.cur = name

    # ---- screens
    def _home(self):
        col = self.screen("home")
        top = self.F(col); top.pack(fill="x", pady=(28, 0))
        self.Badge(self, top, "t", fill="accent", fg="accent_text", square=True).pack(side="left")
        self.L(top, "torchat", "h2").pack(side="left", padx=12)
        self.theme_btn = self.Button(self, top, "☀", self.toggle_theme, kind="ghost", font="h2", padx=10, pady=4)
        self.theme_btn.pack(side="right")
        self.L(col, "Private chat.\nNo strings attached.", "h1").pack(anchor="w", pady=(40, 10))
        self.L(col, "End-to-end encrypted and peer-to-peer over Tor. No account, no phone number, "
                    "no servers - and nothing is ever saved.", fg="muted", wrap=580).pack(anchor="w")
        self.Card(self, col, "+", "Start a chat", "Get an 8-word code and share it with one friend.", self.start).pack(fill="x", pady=(30, 10))
        self.Card(self, col, "→", "Join a chat", "Type the code your friend gave you.", self.show_join).pack(fill="x")
        chips = self.F(col); chips.pack(anchor="w", pady=(22, 0))
        for t in ("No sign-up", "No servers", "IP hidden", "Nothing stored"):
            self.Button(self, chips, "✓ " + t, kind="chip", font="small", padx=10, pady=5, static=True).pack(side="left", padx=(0, 6))
        self.pass_toggle = self.Button(self, col, "+ Add an extra passphrase (optional)", self.toggle_pass, kind="link",
                                       font="normal", padx=0, pady=4)
        self.pass_toggle.pack(anchor="w", pady=(26, 4))
        self.pass_box = self.F(col)
        self.L(self.pass_box, "Agree on it with your friend by another route than the code. You must both type the same one.",
               "small", fg="muted", wrap=580).pack(anchor="w", pady=(0, 6))
        self.pass_field = self.Field(self, self.pass_box, show="•"); self.pass_field.pack(fill="x")
        self.L(col, "Ctrl + and Ctrl − change the text size.", "small", fg="muted").pack(side="bottom", anchor="w", pady=18)

    def _join(self):
        col = self.screen("join")
        self.Button(self, col, "← Back", lambda: self.show("home"), kind="ghost", font="normal", padx=10, pady=5).pack(anchor="w", pady=(24, 0))
        self.L(col, "Join a chat", "h1").pack(anchor="w", pady=(18, 8))
        self.L(col, "Type the 8 words your friend gave you. Capitals, spaces and dashes don't matter, "
                    "and the first 4 letters of each word are enough.", fg="muted", wrap=580).pack(anchor="w")
        self.code_var = self.tk.StringVar()
        self.code_field = self.Field(self, col, font="mono", pady=14); self.code_field.pack(fill="x", pady=(24, 10))
        e = self.code_field.entry; e.configure(textvariable=self.code_var)
        e.bind("<Return>", lambda ev: self.join()); e.bind("<Escape>", lambda ev: self.show("home"))
        self.code_var.trace_add("write", lambda *a: self.check_code())
        self.code_msg = self.L(col, "", "small", fg="muted", wrap=580); self.code_msg.pack(anchor="w")
        self.connect_btn = self.Button(self, col, "Connect", self.join, fill=True, pady=13)
        self.connect_btn.pack(fill="x", pady=(22, 0)); self.connect_btn.set_enabled(False)

    def _wait(self):
        col = self.screen("wait", 640)
        self.wait_cancel = self.Button(self, col, "Cancel", self.new_session, kind="secondary", font="normal", pady=7)
        self.wait_cancel.pack(side="bottom", anchor="e", pady=20)
        self.wait_title = self.L(col, "Getting ready…", "h1"); self.wait_title.pack(anchor="w", pady=(34, 6))
        self.wait_sub = self.L(col, "", fg="muted", wrap=600); self.wait_sub.pack(anchor="w")
        self.code_panel = self.F(col)
        self.L(self.code_panel, "Tell these 8 words to ONE friend - by call, message or in person.", wrap=600).pack(anchor="w")
        grid = self.F(self.code_panel); grid.pack(fill="x", pady=10)
        self.word_chips = []
        for i in range(8):
            ch = self.Chip(self, grid, i + 1); ch.grid(row=i // 4, column=i % 4, sticky="ew", padx=4, pady=4)
            self.word_chips.append(ch)
        for i in range(4): grid.grid_columnconfigure(i, weight=1, uniform="w")
        row = self.F(self.code_panel); row.pack(fill="x")
        self.copy_btn = self.Button(self, row, "Copy code", self.copy_code, kind="secondary", font="normal", pady=6)
        self.copy_btn.pack(side="left")
        self.L(row, "Works once, and only while this window stays open.", "small", fg="muted").pack(side="left", padx=12)
        self.steps_box = self.F(col); self.steps_box.pack(fill="x", pady=(26, 6))
        self.step_rows = []
        for _ in range(3):
            r = self.F(self.steps_box); r.pack(anchor="w", pady=3)
            dot = self.L(r, "○", "bold", fg="muted", anchor="center"); dot.configure(width=2); dot.pack(side="left")
            txt = self.L(r, "", fg="muted"); txt.pack(side="left", padx=10)
            self.step_rows.append((dot, txt))
        self.bar = self.ttk.Progressbar(col, style="TC.Horizontal.TProgressbar", mode="determinate", maximum=100)
        self.bar.pack(fill="x", pady=(10, 8))
        self.status = self.L(col, "", "small", fg="muted", wrap=600); self.status.pack(anchor="w")
        self.elapsed = self.L(col, "", "small", fg="muted"); self.elapsed.pack(anchor="w", pady=(2, 0))
        self.tips = self.L(col, "Still connecting?\n• Your friend must keep their window open - every restart makes a NEW code.\n"
                                "• Check the date and time on both devices.\n"
                                "• Some networks block Tor: try another Wi-Fi, mobile data or a VPN (see the README for bridges).",
                           "small", wrap=600)
        self.details = self.reg(self.tk.Text(col, height=5, wrap="word", state="disabled", font=self.f["small"], relief="flat",
                                             bd=0, padx=10, pady=8, highlightthickness=0), bg="surface2", fg="muted")

    def _verify(self):
        col = self.screen("verify")
        self.Badge(self, col, "✓", fill="accent_soft", fg="accent_fg").pack(anchor="w", pady=(44, 16))
        self.L(col, "Compare safety codes", "h1").pack(anchor="w", pady=(0, 8))
        self.L(col, "Call your friend or meet in person - NOT in this chat - and read your codes to each other. "
                    "If they are exactly the same, nobody is listening in.", fg="muted", wrap=580).pack(anchor="w")
        grid = self.F(col); grid.pack(fill="x", pady=26)
        self.sas_chips = []
        for i in range(5):
            ch = self.Chip(self, grid); ch.grid(row=0, column=i, sticky="ew", padx=4); self.sas_chips.append(ch)
            grid.grid_columnconfigure(i, weight=1, uniform="s")
        row = self.F(col); row.pack(fill="x")
        self.Button(self, row, "They don't match", lambda: self.finish_verify(False), kind="danger-ghost", pady=12).pack(side="left")
        self.Button(self, row, "They match", lambda: self.finish_verify(True), pady=12).pack(side="right")
        self.L(col, "Different codes mean someone may be in the middle: press \"They don't match\" and start again with a new code.",
               "small", fg="muted", wrap=580).pack(anchor="w", pady=(22, 0))

    def _chat(self):
        tk, scr = self.tk, self.screen("chat", 0)
        head = self.F(scr, bg="surface"); head.pack(fill="x")
        hin = self.F(head, bg="surface"); hin.pack(fill="x", padx=18, pady=12)
        self.Badge(self, hin, "F", bg="surface").pack(side="left")
        tbox = self.F(hin, bg="surface"); tbox.pack(side="left", padx=12)
        self.L(tbox, "Your friend", "bold", bg="surface").pack(anchor="w")
        self.chat_status = self.L(tbox, "● End-to-end encrypted · via Tor", "small", fg="ok", bg="surface")
        self.chat_status.pack(anchor="w")
        self.Button(self, hin, "End chat", self.end_chat, kind="danger-ghost", font="normal", bg="surface", pady=6).pack(side="right")
        self.sas_lbl = self.L(hin, "", "small", fg="muted", bg="surface", justify="right", anchor="e")
        self.sas_lbl.pack(side="right", padx=14)
        self.reg(tk.Frame(scr, height=1, bd=0, highlightthickness=0), bg="border").pack(fill="x")
        bottom = self.F(scr); bottom.pack(side="bottom", fill="x")
        self.banner = self.F(bottom, bg="surface2")
        self.L(self.banner, "The chat has ended. Everything you received is wiped when you leave.", bg="surface2",
               wrap=520).pack(side="left", padx=16, pady=12)
        self.Button(self, self.banner, "Back to start", self.new_session, kind="primary", font="normal", bg="surface2", pady=6).pack(side="right", padx=12)
        self.xfer_box = self.F(bottom)
        self.xfer_lbl = self.L(self.xfer_box, "", "small", fg="muted"); self.xfer_lbl.pack(anchor="w")
        self.xfer_bar = self.ttk.Progressbar(self.xfer_box, style="TC.Horizontal.TProgressbar", mode="determinate", maximum=100)
        self.xfer_bar.pack(fill="x", pady=(4, 0))
        self.hint = self.L(bottom, "", "small", fg="muted"); self.hint.pack(anchor="w", padx=20, pady=(8, 0))
        row = self.F(bottom); row.pack(fill="x", padx=16, pady=(6, 16))
        self.attach_btn = self.Button(self, row, "+ File", self.attach, kind="secondary", font="normal", pady=12)
        self.attach_btn.pack(side="left")
        self.send_btn = self.Button(self, row, "Send", self.send, pady=12); self.send_btn.pack(side="right")
        self.composer = self.Field(self, row, pady=12); self.composer.pack(side="left", fill="x", expand=True, padx=8)
        self.composer.entry.bind("<Return>", lambda e: self.send())
        mid = self.F(scr); mid.pack(fill="both", expand=True)
        self.msg_canvas = self.reg(tk.Canvas(mid, highlightthickness=0, bd=0, yscrollincrement=24), bg="bg")
        sb = self.ttk.Scrollbar(mid, orient="vertical", style="TC.Vertical.TScrollbar", command=self.msg_canvas.yview)
        self.msg_canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y"); self.msg_canvas.pack(side="left", fill="both", expand=True)
        self.msg_frame = self.F(self.msg_canvas)
        self.msg_win = self.msg_canvas.create_window(0, 0, window=self.msg_frame, anchor="nw")
        self.msg_frame.bind("<Configure>", lambda e: self.msg_canvas.configure(scrollregion=(0, 0, e.width, e.height)))
        self.msg_canvas.bind("<Configure>", self._on_chat_resize)

    def _error(self):
        col = self.screen("error")
        self.Badge(self, col, "!", fill="danger_soft", fg="danger").pack(anchor="w", pady=(48, 16))
        self.err_title = self.L(col, "", "h1"); self.err_title.pack(anchor="w")
        self.err_text = self.L(col, "", wrap=580); self.err_text.pack(anchor="w", pady=(10, 0))
        self.err_tips = self.L(col, "", fg="muted", wrap=580); self.err_tips.pack(anchor="w", pady=(16, 0))
        self.Button(self, col, "Back to start", self.new_session, pady=12).pack(anchor="w", pady=28)

    def show_error(self, title, text, tips=""):
        text = str(text); text = text[:1].upper() + text[1:]
        self.err_title.configure(text=title); self.err_text.configure(text=text); self.err_tips.configure(text=tips)
        self.show("error")

    # ---- actions
    def start(self):
        self.role, self.m.passphrase = "host", self.pass_field.entry.get(); self.m.start_host()

    def show_join(self):
        self.code_var.set(""); self.show("join"); self.code_field.entry.focus_set()

    def toggle_pass(self):
        if self.pass_box.winfo_ismapped():
            self.pass_box.pack_forget(); self.pass_toggle.set_text("+ Add an extra passphrase (optional)")
        else:
            self.pass_box.pack(after=self.pass_toggle, fill="x"); self.pass_toggle.set_text("− Hide extra passphrase")
            self.pass_field.entry.focus_set()

    def check_code(self):
        text = self.code_var.get(); n = len(re.findall(r"[a-zA-Z]+", text))
        ok, msg, tone = False, "", "muted"
        if text.strip() and n < CODE_WORDS: msg = "%d of %d words" % (n, CODE_WORDS)
        elif text.strip():
            try: parse_code(text); ok, msg, tone = True, "✓ The code looks right.", "ok"
            except ValueError as ex: msg, tone = str(ex), "danger"
        self.code_msg.configure(text=msg); self.recolor(self.code_msg, fg=tone); self.connect_btn.set_enabled(ok)

    def join(self):
        if not self.connect_btn.enabled: return
        try:
            self.role, self.m.passphrase = "join", self.pass_field.entry.get(); self.m.start_join(self.code_var.get())
        except ValueError as ex:
            self.code_msg.configure(text=str(ex)); self.recolor(self.code_msg, fg="danger")

    def copy_code(self):
        self.root.clipboard_clear(); self.root.clipboard_append(" ".join(self.m.code_words or []))
        self.copy_btn.set_text("Copied ✓")
        self.root.after(2000, lambda: self.copy_btn.winfo_exists() and self.copy_btn.set_text("Copy code"))

    def _sender(self):                                   # sends in order, off the window's thread (no freezes)
        while True:
            m, text = self.sendq.get()
            try: m.send_text(text)
            except Exception as ex: m.emit(kind="sys", text="Not sent: %s" % ex)

    def send(self):
        if not self.send_btn.enabled: return
        t = self.composer.entry.get().strip()
        if not t: return
        if len(t.encode()) > MAXMSG: return              # the counter under the box is already red
        self.composer.entry.delete(0, "end"); self.sendq.put((self.m, t))

    def attach(self):
        if not self.attach_btn.enabled: return
        paths = self.fd.askopenfilenames(title="Choose files to send")
        if not paths: return
        m = self.m
        def work():
            for p in paths:
                try: m.send_file(p)
                except Exception as ex: m.emit(kind="sys", text="Could not send %s: %s" % (os.path.basename(p), ex))
        threading.Thread(target=work, daemon=True).start()

    def save(self, fid):
        start = default_save_dir(); start = start if os.path.isdir(start) else os.path.expanduser("~")
        dest = self.fd.askdirectory(title="Save into which folder?", initialdir=start)
        if not dest: return
        try: self.add_sys("Saved to " + self.m.save_file(fid, dest))
        except Exception as ex: self.add_sys("Could not save: %s" % ex)

    def new_session(self):
        try: self.m.end()
        except Exception: pass
        self.m, self.ready_shown, self.hint_shown, self.last_sys = Messenger(), None, None, ""
        for w in self.msg_frame.winfo_children(): w.destroy()
        self.bubbles.clear(); self.sys_labels.clear()
        self.banner.pack_forget(); self.xfer_box.pack_forget()
        self.show("home")

    def end_chat(self):
        if self.m.stage == "chat" and not self.mb.askokcancel("torchat", "End the chat and delete everything received?"): return
        self.new_session()

    def finish_verify(self, ok):
        self.m.confirm(ok)
        if not ok:
            try: self.m.end()
            except Exception: pass
            self.show_error("Stopped for your safety", "The safety codes did not match, so nothing was sent. "
                            "Someone may be interfering. Start again with a new code.")

    def on_close(self):
        if self.m.stage in ("starting", "invite", "connecting", "verify", "chat"):
            if not self.mb.askokcancel("torchat", "End the chat and delete everything received?"): return
        try: self.m.end()
        finally: self.root.destroy()

    # ---- chat area
    def _on_chat_resize(self, e):
        self.msg_canvas.itemconfigure(self.msg_win, width=e.width)
        wrap = max(200, int(e.width * 0.62))
        if abs(wrap - self.wrap) > 6:
            self.wrap = wrap
            if self._rewrap_job: self.root.after_cancel(self._rewrap_job)
            self._rewrap_job = self.root.after(60, self._rewrap)

    def _rewrap(self):
        self._rewrap_job = None
        self.bubbles = [b for b in self.bubbles if b.winfo_exists()]
        for b in self.bubbles: b._paint()
        for l in self.sys_labels:
            if l.winfo_exists(): l.configure(wraplength=self.wrap + 120)

    def _wheel(self, e):
        if self.cur != "chat" or self.msg_frame.winfo_height() <= self.msg_canvas.winfo_height(): return
        d = -1 if (getattr(e, "num", 0) == 4 or getattr(e, "delta", 0) > 0) else 1
        self.msg_canvas.yview_scroll(d * 2, "units")

    def _row(self, side):
        row = self.F(self.msg_frame); row.pack(fill="x", padx=18, pady=3)
        if side == "sys": return row
        inner = self.F(row); inner.pack(side="right" if side == "me" else "left"); return inner

    def _scroll(self, force):
        if force: self.root.after(40, lambda: self.msg_canvas.yview_moveto(1.0))

    def _at_bottom(self): return self.msg_canvas.yview()[1] > 0.98

    def _stamp(self, inner, side, ts):
        self.L(inner, time.strftime("%H:%M", time.localtime(ts)), "small", fg="muted").pack(anchor="e" if side == "me" else "w", pady=(3, 0))

    def add_text(self, side, text, ts):
        follow = side == "me" or self._at_bottom()
        inner = self._row(side)
        fill, fg = ("me", "me_text") if side == "me" else ("peer", "peer_text")
        b = self.Bubble(self, inner, [(text, "normal", fg)], fill, copy=text); b.pack(anchor="e" if side == "me" else "w")
        self.bubbles.append(b); self._stamp(inner, side, ts); self._scroll(follow)

    def add_sys(self, text):
        follow = self._at_bottom()
        lab = self.L(self._row("sys"), text, "small", fg="muted", wrap=self.wrap + 120, justify="center", anchor="center")
        lab.pack(pady=6); self.sys_labels.append(lab); self._scroll(follow)

    def add_file(self, e, incoming):
        follow = not incoming or self._at_bottom()
        side = "peer" if incoming else "me"
        inner = self._row(side)
        fg, sub = ("peer_text", "peer_sub") if incoming else ("me_text", "me_sub")
        meta = human(e["size"])
        if incoming: meta += " · kept private until you save it"
        elif e.get("scrubbed"): meta += " · photo details removed"
        elif not e.get("image"): meta += " · hidden details (author, location) are NOT removed from this kind of file"
        lines = [(e["name"], "bold", fg), (meta, "small", sub)]
        if e.get("warn"): lines.append(("⚠ Program-type file - only open it if you fully trust your friend.", "small", "warn" if incoming else sub))
        b = self.Bubble(self, inner, lines, "peer" if incoming else "me", copy=e["name"])
        b.pack(anchor="w" if incoming else "e"); self.bubbles.append(b)
        if incoming:
            self.Button(self, inner, "Save…", lambda fid=e["fid"]: self.save(fid), kind="secondary", font="small",
                        padx=12, pady=5).pack(anchor="w", pady=(6, 0))
        self._stamp(inner, side, e["ts"]); self._scroll(follow)

    # ---- events from the engine
    def handle(self, e):
        k = e["kind"]
        if k == "stage": self.on_stage(e["stage"])
        elif k == "sys": self.last_sys = e["text"]; self.add_sys(e["text"])
        elif k == "in": self.add_text("peer", e["text"], e["ts"])
        elif k == "out": self.add_text("me", e["text"], e["ts"])
        elif k == "file_in": self.add_file(e, True)
        elif k == "file_out": self.add_file(e, False)

    def on_stage(self, s):
        self.stage_since = time.time()
        host = self.role == "host"
        if s in ("starting", "invite", "connecting"):
            steps = (("Connect to the Tor network", "Publish your private address and wait for your friend", "Set up encryption")
                     if host else ("Connect to the Tor network", "Find your friend's private address", "Set up encryption"))
            for (dot, txt), t in zip(self.step_rows, steps): txt.configure(text=t)
            self.tips.pack_forget(); self.details.pack_forget()
        if s == "starting":
            self.wait_title.configure(text="Getting ready…")
            self.wait_sub.configure(text="Creating your private code and starting Tor." if host else "Starting Tor to look for your friend.")
            self.code_panel.pack_forget(); self.show("wait")
        elif s == "invite":
            self.wait_title.configure(text="Your pairing code")
            self.wait_sub.configure(text="Share it now - your friend can start joining while Tor gets ready.")
            for ch, w in zip(self.word_chips, self.m.code_words or []): ch.set(w)
            self.copy_btn.set_text("Copy code")
            self.code_panel.pack(after=self.wait_sub, fill="x", pady=(18, 0)); self.show("wait")
        elif s == "connecting":
            self.wait_title.configure(text="Connecting to your friend…")
            self.wait_sub.configure(text="Everything goes through Tor, so this can take a minute.")
            self.code_panel.pack_forget(); self.show("wait")
        elif s == "verify":
            for ch, g in zip(self.sas_chips, (self.m.sas or "").split()): ch.set(g)
            self.show("verify")
        elif s == "chat":
            self.sas_lbl.configure(text="Safety code\n" + (self.m.sas or ""))
            self.ready_shown = self.hint_shown = None
            self.banner.pack_forget(); self.composer.entry.configure(state="normal")
            self.chat_status.configure(text="\u25cf End-to-end encrypted \u00b7 via Tor"); self.recolor(self.chat_status, fg="ok")
            self.add_sys("Connected. Messages are end-to-end encrypted and never saved to disk.")
            self.show("chat"); self.composer.entry.focus_set()
        elif s == "closed":
            if self.cur == "chat":
                self.banner.pack(fill="x", before=self.hint, padx=16, pady=(10, 0))
                self.composer.entry.configure(state="disabled"); self.root.focus_set()
                self.send_btn.set_enabled(False); self.attach_btn.set_enabled(False); self.hint.configure(text="")
                self.recolor(self.chat_status, fg="muted"); self.chat_status.configure(text="● Disconnected")
            elif self.cur in ("wait", "verify"):
                self.show_error("Session closed", self.last_sys or "The connection was closed.", GUI_TIPS)
        elif s == "error":
            self.show_error("Couldn't connect", self.m.error_text, GUI_TIPS)

    def _update_wait(self):
        m, secs = self.m, int(time.time() - self.stage_since)
        self.bar["value"] = m.progress
        self.status.configure(text=m.detail or ("Tor is starting (%d%%)…" % m.progress))
        self.elapsed.configure(text="%d:%02d elapsed" % divmod(secs, 60))
        active = 2 if m.detail.startswith("Connected to your friend") else (1 if m.progress >= 100 else 0)
        for i, (dot, txt) in enumerate(self.step_rows):
            glyph, tone = ("✓", "ok") if i < active else (("●", "accent_fg") if i == active else ("○", "muted"))
            if dot.cget("text") != glyph:
                dot.configure(text=glyph); self.recolor(dot, fg=tone); self.recolor(txt, fg="muted" if i > active else "text")
        if secs > 90 and not self.tips.winfo_ismapped():
            self.tips.pack(anchor="w", pady=(14, 6), after=self.elapsed); self.details.pack(fill="x", after=self.tips)
        if m.tail != self.tail_shown and self.details.winfo_ismapped():
            self.tail_shown = list(m.tail)
            d = self.details; d.configure(state="normal"); d.delete("1.0", "end"); d.insert("end", "\n".join(m.tail)); d.configure(state="disabled")

    def _update_chat(self):
        m = self.m
        if m.stage == "chat":
            ready = m.ready
            if ready != self.ready_shown:
                self.ready_shown = ready; self.send_btn.set_enabled(ready); self.attach_btn.set_enabled(ready)
            n = len(self.composer.entry.get().encode())
            hint = (("Waiting for your friend to confirm the safety code…", "muted") if not ready else
                    ("%d / %d bytes" % (n, MAXMSG), "danger" if n > MAXMSG else "muted") if n > MAXMSG - 300 else ("", "muted"))
            if hint != self.hint_shown:
                self.hint_shown = hint; self.hint.configure(text=hint[0]); self.recolor(self.hint, fg=hint[1])
        ts = list(m.transfers.values())
        if ts:
            t = ts[0]; pct = 100 * t["done"] // max(1, t["size"])
            self.xfer_lbl.configure(text="%s %s · %d%%%s" % ("Receiving" if t["dir"] == "in" else "Sending", t["name"], pct,
                                                                 "  (+%d more)" % (len(ts) - 1) if len(ts) > 1 else ""))
            self.xfer_bar["value"] = pct
            if not self.xfer_box.winfo_ismapped(): self.xfer_box.pack(fill="x", padx=20, pady=(8, 0), before=self.hint)
        elif self.xfer_box.winfo_ismapped():
            self.xfer_box.pack_forget()

    def pump(self):
        try:
            try:
                while True: self.handle(self.m.q.get_nowait())
            except queue.Empty:
                pass
            if self.cur == "wait": self._update_wait()
            elif self.cur == "chat": self._update_chat()
        finally:
            self.root.after(100, self.pump)

    def run(self):
        self.root.mainloop()



# ======================================================================== self-test + entry point
def selftest(limit=300):
    """Runs a host and a guest (two separate Tor processes) on THIS device and reports each step.
       PASS = the app and Tor work end to end here; a failing chat with another device is then a network / clock / old-code problem."""
    t0 = time.time()
    def log(msg): print("[%3ds] %s" % (time.time() - t0, msg), flush=True)
    class Term:
        def __init__(self): self.prog, self.detail, self.tail = 0, "", []
        def set_progress(self, p): self.prog = p
        def set_detail(self, t): self.detail = t
        def set_tail(self, l): self.tail = list(l)
        def show(self, m): pass
    hu, gu = Term(), Term()
    host, guest = Tor(hu), Tor(gu)
    res, ok = {}, False
    def run(name, fn):
        try: res[name] = fn()
        except Exception as ex: res[name + "_err"] = str(ex)
    try:
        idx = new_code(); derived = derive(parse_code(" ".join(code_words(idx))))       # same path real users take
        onion, _ = onion_from_seed(derived[:32])
        log("Step 1/4: starting the HOST Tor ...")
        threading.Thread(target=run, args=("host", lambda: host.host(derived)), daemon=True).start()
        for _ in range(240):
            if os.path.exists(host.dir + "/hs/hostname") or "host_err" in res: break
            time.sleep(0.25)
        if "host_err" in res or not os.path.exists(host.dir + "/hs/hostname"):
            log("FAILED: could not start the host: %s" % res.get("host_err", "no onion address")); return 1
        log("Step 2/4: starting the GUEST Tor and looking for the host ...")
        threading.Thread(target=run, args=("guest", lambda: guest.join(onion, b32(derived[32:64]))), daemon=True).start()
        last = ""
        while time.time() - t0 < limit and not ("host" in res and "guest" in res):
            if "host_err" in res or "guest_err" in res: break
            line = "host Tor %d%% | guest Tor %d%% | %s" % (hu.prog, gu.prog, gu.detail[:110])
            if line != last: log(line); last = line
            time.sleep(2)
        if not ("host" in res and "guest" in res):
            log("FAILED to connect.")
            for k in ("host_err", "guest_err"):
                if k in res: log("  %s: %s" % (k, res[k]))
            log("  host: %s" % (hu.detail or "-")); log("  guest: %s" % (gu.detail or "-"))
            for who, u in (("host", hu), ("guest", gu)):
                for l in u.tail[-5:]: log("  [%s tor] %s" % (who, l))
            log("What this means: if Tor is stuck below 100%, your network blocks Tor or the clock is wrong (try --bridges or --firewall).")
            return 1
        log("Step 3/4: connected through Tor. Setting up encryption ...")
        out = {}
        def hs(role, sock): out[role] = handshake(sock, role, derived[64:96].hex())[1]
        th = [threading.Thread(target=hs, args=("host", res["host"])), threading.Thread(target=hs, args=("join", res["guest"]))]
        for t in th: t.start()
        for t in th: t.join(60)
        if len(out) == 2 and out["host"] == out["join"]:
            ok = True
            log("Step 4/4: encrypted handshake OK. Both sides show the same safety code: %s" % out["host"])
            log("RESULT: PASS. The app and Tor work end to end on this device.")
        else:
            log("FAILED: the encrypted handshake did not complete (%s)." % out)
    finally:
        for t in (host, guest): t.stop()
    return 0 if ok else 1


def pick_interface(args):
    if args.tui: return "tui"
    termux = os.path.isdir("/data/data/com.termux") or "TERMUX_VERSION" in os.environ
    have_display = sys.platform == "darwin" or os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
    if args.gui or (have_display and not termux):
        try:
            import tkinter  # noqa: F401
            return "gui"
        except ImportError:
            if args.gui: print("The window needs tkinter (Debian/Ubuntu: sudo apt install python3-tk). Using the text screen instead.")
    return "tui"


def main():
    ap = argparse.ArgumentParser(description="Private chat with anyone in the world - end-to-end encrypted, no servers, no browser.")
    ap.add_argument("--gui", action="store_true", help="force the desktop window")
    ap.add_argument("--tui", action="store_true", help="force the simple text screen (default on phones/servers)")
    ap.add_argument("--pass", dest="passphrase", action="store_true", help="text screen: ask for an extra passphrase you agree on with your friend")
    ap.add_argument("--no-cache", action="store_true", help="do not reuse Tor's public network cache between runs (slower start, nothing kept on disk)")
    ap.add_argument("--clear-cache", action="store_true", help="delete the Tor network cache and exit")
    ap.add_argument("--bridges", metavar="FILE", help="file with Tor bridge lines, for networks that block Tor (get them at bridges.torproject.org)")
    ap.add_argument("--firewall", action="store_true", help="for networks that only allow web ports 80/443")
    ap.add_argument("--selftest", action="store_true", help="test the whole connection on this device (host + guest) and report each step")
    ap.add_argument("--debug", action="store_true", help="print Tor's log lines to this terminal (for troubleshooting)")
    args = ap.parse_args()
    if args.clear_cache:
        clear_cache(); print("Cache deleted."); return
    Tor.use_cache, Tor.debug, Tor.firewall = not args.no_cache, args.debug, args.firewall
    if args.bridges:
        try: Tor.bridges, Tor.plugins = load_bridges(args.bridges)
        except (ValueError, OSError) as ex:
            print("Bridge file problem: %s" % ex, file=sys.stderr); sys.exit(2)
    harden()
    def _stop(*_): raise KeyboardInterrupt
    for name in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, name): signal.signal(getattr(signal, name), _stop)
    sweep_stale()
    if args.selftest: sys.exit(selftest())
    if pick_interface(args) == "gui":
        app = Gui()
        try: app.run()
        finally: app.m.end()
    else:
        pw = ""
        if args.passphrase:
            import getpass; pw = getpass.getpass("Extra passphrase (must match your friend's): ")
        m = Messenger(pw)
        try: Tui(m).run()
        except (KeyboardInterrupt, EOFError): pass
        finally: m.end()
    sys.exit(0)


if __name__ == "__main__":
    main()
