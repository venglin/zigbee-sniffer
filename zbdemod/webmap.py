"""`zbdemod map`: a live map of the Zigbee networks in range, in the browser.

A small HTTP server (standard library only) serves the page in zbdemod/web/
and a JSON snapshot of the NetworkMap. The capture runs in the main thread:
live from the HackRF (one channel, or hopping over several), or from
recordings / PCAP files.

    GET  /                 the map page
    GET  /api/state?v=N    snapshot (204 when nothing changed since version N)
    POST /api/tune         {"channels": [15] | "11-26", "dwell": 5}   (live only)
    POST /api/reset        forget everything heard so far
"""

from __future__ import annotations

import json
import sys
import threading
import time
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import numpy as np

from . import cli, phy
from .netmap import NetworkMap, load_names
from .pcap import read_pcap

WEB_DIR = Path(__file__).with_name("web")
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}


class Control:
    """State shared by the capture loop and the HTTP handlers."""

    def __init__(self, mode: str, channels: list[int], dwell: float):
        self.lock = threading.Lock()
        self.mode = mode  # live | file | pcap
        self.channels = channels
        self.dwell = dwell
        self.plan_version = 0
        self.status: dict = {"mode": mode, "channels": channels, "dwell": dwell, "current": None}

    def set_plan(self, channels: list[int], dwell: float) -> None:
        with self.lock:
            self.channels, self.dwell = channels, dwell
            self.plan_version += 1
            self.status.update(channels=channels, dwell=dwell)

    def plan(self) -> tuple[int, list[int], float]:
        with self.lock:
            return self.plan_version, list(self.channels), self.dwell

    def update(self, **kw) -> None:
        with self.lock:
            self.status.update(kw)

    def view(self) -> dict:
        with self.lock:
            return dict(self.status)


# ------------------------------------------------------------------- server
class MapServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, model: NetworkMap, control: Control):
        self.model = model
        self.control = control
        self.any_host = addr[0] not in ("127.0.0.1", "localhost", "::1")
        super().__init__(addr, Handler)


class Handler(BaseHTTPRequestHandler):
    server: MapServer
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep the console for the capture status
        pass

    def _host_ok(self) -> bool:
        """Refuse foreign Host headers (DNS rebinding) unless bound to a public address."""
        if self.server.any_host:
            return True
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].lower()
        if host.startswith("[") and "]" in host:
            host = host[: host.index("]") + 1]
        return host in LOCAL_HOSTS

    def _send(self, code: int, body: bytes = b"", ctype: str = "application/json") -> None:
        self.send_response(code)
        if body:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, separators=(",", ":")).encode())

    def do_GET(self):
        if not self._host_ok():
            return self._send(HTTPStatus.FORBIDDEN)
        url = urlsplit(self.path)
        if url.path in STATIC:
            name, ctype = STATIC[url.path]
            return self._send(200, (WEB_DIR / name).read_bytes(), ctype)
        if url.path == "/api/state":
            since = parse_qs(url.query).get("v", [""])[0]
            model = self.server.model
            if since and since == str(model.version):
                return self._send(HTTPStatus.NO_CONTENT)
            snap = model.snapshot()
            snap["source"] = self.server.control.view()
            return self._json(snap)
        return self._send(HTTPStatus.NOT_FOUND)

    do_HEAD = do_GET

    def do_POST(self):
        # Read the body first: on a kept-alive connection unread bytes would be
        # taken for the next request.
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if not 0 <= length <= 4096:
            self.close_connection = True
            return self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        raw = self.rfile.read(length)
        if not self._host_ok():
            return self._send(HTTPStatus.FORBIDDEN)
        # Only same-origin scripts can send application/json (no CORS preflight answered).
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            return self._send(HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
        try:
            body = json.loads(raw or b"{}")
            if not isinstance(body, dict):
                raise ValueError
        except ValueError:
            return self._json({"error": "bad request"}, 400)
        path = urlsplit(self.path).path
        ctl = self.server.control
        if path == "/api/reset":
            self.server.model.reset()
            return self._json({"ok": True})
        if path == "/api/tune":
            if ctl.mode != "live":
                return self._json({"error": "not a live capture"}, 409)
            try:
                chans = body.get("channels", [])
                channels = cli.parse_channels(chans) if isinstance(chans, str) else [int(c) for c in chans]
                for c in channels:
                    phy.channel_freq(c)
                dwell = float(body.get("dwell", ctl.dwell))
                if not channels or not 0.5 <= dwell <= 600:
                    raise ValueError
            except (ValueError, TypeError):
                return self._json({"error": "channels must be 11..26, dwell 0.5..600 s"}, 400)
            ctl.set_plan(channels, dwell)
            return self._json({"ok": True, "channels": channels, "dwell": dwell})
        return self._send(HTTPStatus.NOT_FOUND)


def start_server(model: NetworkMap, control: Control, host: str, port: int) -> MapServer:
    last: OSError | None = None
    for p in ([port] if port == 0 else range(port, port + 10)):
        try:
            srv = MapServer((host, p), model, control)
            break
        except OSError as exc:  # port in use: try the next one
            last = exc
    else:
        raise SystemExit(f"cannot listen on {host}:{port}..{port + 9}: {last}")
    threading.Thread(target=srv.serve_forever, name="map-http", daemon=True).start()
    return srv


# ------------------------------------------------------------------ capture
class MapSink(cli.Printer):
    """Printer that also feeds the network map."""

    def __init__(self, model: NetworkMap, args):
        super().__init__(
            False,
            cli.open_pcap(args.pcap),
            out=sys.stderr if args.pcap == "-" else None,
            quiet=not args.verbose,
            pcap_bad=args.bad,
        )
        self.model = model

    def frame(self, f, wall: float) -> None:
        self.model.add_frame(f, wall)
        super().frame(f, wall)


def capture_live(args, model: NetworkMap, ctl: Control, sink: MapSink) -> int:
    plan_v, channels, dwell = ctl.plan()
    dev = cli._open_hackrf(args, channels[0])
    stream = cli._Stream(dev, args.fs)
    settle = int(0.08 * args.fs) * 2  # bytes to drop after a retune
    idx, cur = 0, channels[0]
    demod = cli.make_demod(args, cur, args.offset, args.fs)
    t_switch = time.time() + dwell
    ctl.update(current=cur, lna=dev.lna_db, vga=dev.vga_db, amp=dev.amp, started=time.time())
    dev.start()
    busy, t_begin, t_stat = 0.0, time.time(), 0.0
    rc = 0
    try:
        while True:
            now = time.time()
            v, new_channels, new_dwell = ctl.plan()
            tune = False
            if v != plan_v:
                plan_v, channels, dwell, idx, tune = v, new_channels, new_dwell, 0, True
            elif len(channels) > 1 and now >= t_switch:
                idx, tune = (idx + 1) % len(channels), True
            if tune:
                model.channel_status(cur, _noise(demod))
                cur = channels[idx]
                dev.retune(phy.channel_freq(cur) + args.offset, settle)
                demod = cli.make_demod(args, cur, args.offset, args.fs)
                stream.reset_clock()
                t_switch = time.time() + dwell
                ctl.update(current=cur)
            iq = stream.next_iq(timeout=0.5)
            if iq is None:
                if not dev.is_streaming():
                    print("# HackRF stopped streaming", file=sys.stderr)
                    rc = 1
                    break
                continue
            t = time.perf_counter()
            for f in demod.process(iq):
                sink.frame(f, stream.t0 + f.sample / args.fs)
            busy += time.perf_counter() - t
            if now - t_stat > 1.0:
                t_stat = now
                model.channel_status(cur, _noise(demod))
                ctl.update(
                    clip=100.0 * stream.clip / max(1, 2 * stream.samples),
                    dropped=100.0 * dev.dropped_bytes / max(1, dev.received_bytes),
                    cpu=100.0 * busy / max(1e-9, now - t_begin),
                    noise=_noise(demod),
                )
    except KeyboardInterrupt:
        pass
    except cli.PipeClosed:
        cli._pipe_closed(sink)
    finally:
        dev.close()
    return rc


def _noise(demod) -> float | None:
    nf = demod.noise_floor
    return float(10 * np.log10(nf)) if nf else None


def load_inputs(args, model: NetworkMap, ctl: Control, sink: MapSink) -> None:
    """Feed recordings and PCAP files into the map (as fast as they decode)."""
    for path in args.read or []:
        n = 0
        with open(path, "rb") as f:
            for rec in read_pcap(f):
                model.add(rec.psdu, rec.timestamp, fcs_ok=rec.fcs_ok, channel=rec.channel)
                n += 1
        print(f"# {path}: {n} frames", file=sys.stderr)
    for path in args.file or []:
        fargs = SimpleNamespace(
            input=path,
            fs=None,
            offset=None,
            format=None,
            channel=args.channel_list[0] if len(args.channel_list or []) == 1 else None,
            threshold=args.threshold,
            bad=args.bad,
            method=args.method,
            detector=args.detector,
        )
        cli.decode_file(fargs, sink, verbose=True)
    ctl.update(done=True)


def main(args) -> int:
    live = not (args.read or args.file)
    names = load_names(args.names) if args.names else {}
    if args.names:
        print(f"# {len(names)} device names from {args.names}", file=sys.stderr)
    args.channel_list = cli.parse_channels(args.channels) if args.channels else None
    channels = args.channel_list or [11]
    model = NetworkMap(names=names, live=live)
    ctl = Control("live" if live else ("pcap" if args.read and not args.file else "file"), channels, args.dwell)
    srv = start_server(model, ctl, args.host, args.port)
    host = "localhost" if args.host in ("127.0.0.1", "0.0.0.0", "::", "") else args.host
    url = f"http://{host}:{srv.server_address[1]}/"
    print(f"# network map at {url}  (Ctrl+C to stop)", file=sys.stderr)
    if not args.no_browser:
        webbrowser.open(url)
    sink = MapSink(model, args)
    try:
        if live:
            hop = f"hopping {channels}, {args.dwell:g} s each" if len(channels) > 1 else f"channel {channels[0]}"
            print(f"# HackRF: {hop}", file=sys.stderr)
            return capture_live(args, model, ctl, sink)
        load_inputs(args, model, ctl, sink)
        print("# all inputs loaded; the map stays up until Ctrl+C", file=sys.stderr)
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 0
    finally:
        srv.shutdown()
