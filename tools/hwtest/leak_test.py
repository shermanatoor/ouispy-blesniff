"""Does a dashboard connect/disconnect cycle leak heap?

    python tools/hwtest/leak_test.py [cycles]

Host must be joined to the device AP. Heap is read over USB serial (so the
measurement path never touches the network) while the test opens and closes
WebSocket and HTTP connections over Wi-Fi. Each cycle:

    idle -> open WS, stream for a while -> close WS -> settle -> idle

If heap after settling steps down cycle over cycle, connections are leaking.
Phase 2 repeats the same with plain HTTP requests only, to separate a
WebSocket-client leak from a request-object leak.
"""
import base64
import json
import os
import socket
import struct
import sys
import time
import urllib.request

import serial
import serial.tools.list_ports

CYCLES = int(sys.argv[1]) if len(sys.argv) > 1 else 4
HOST = "192.168.4.1"

ser = None


def heap(settle=2.0):
    """Free heap over serial, after letting cleanupClients() run."""
    time.sleep(settle)
    for _ in range(3):
        ser.reset_input_buffer()
        ser.write(b"CMD:STATUS\n")
        ser.flush()
        t_end = time.time() + 2.0
        while time.time() < t_end:
            l = ser.readline().decode("utf-8", "replace").strip()
            if l.startswith("{"):
                try:
                    d = json.loads(l)
                    return d["heap_free"], d.get("ap_stations"), d.get("reset")
                except Exception:
                    pass
    return None, None, None


def ws_open():
    """Minimal RFC6455 client handshake against /ws."""
    s = socket.create_connection((HOST, 80), timeout=8)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall(("GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
               "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
               "Sec-WebSocket-Version: 13\r\n\r\n" % (HOST, key)).encode())
    s.settimeout(6)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(1024)
        if not chunk:
            raise IOError("handshake closed")
        buf += chunk
    if b"101" not in buf.split(b"\r\n")[0]:
        raise IOError("no upgrade: %r" % buf[:80])
    return s


def ws_drain(s, secs):
    """Read frames for `secs`, replying to pings; returns bytes seen."""
    end = time.time() + secs
    total = 0
    s.settimeout(1.0)
    while time.time() < end:
        try:
            d = s.recv(8192)
        except socket.timeout:
            continue
        except Exception:
            break
        if not d:
            break
        total += len(d)
    return total


def ws_close(s):
    try:
        # masked close frame
        m = os.urandom(4)
        s.sendall(b"\x88\x82" + m + bytes(b ^ m[i % 4] for i, b in enumerate(struct.pack(">H", 1000))))
        time.sleep(0.2)
    except Exception:
        pass
    try:
        s.close()
    except Exception:
        pass


def http_get(path="/api/config"):
    try:
        with urllib.request.urlopen("http://%s%s" % (HOST, path), timeout=6) as r:
            return len(r.read())
    except Exception as e:
        return -1


dev = next(p.device for p in serial.tools.list_ports.comports() if "303A" in (p.hwid or "").upper())
ser = serial.Serial(dev, 115200, timeout=0.2)
time.sleep(0.3)

base, sta, rst = heap()
print("baseline heap=%s ap_stations=%s reset=%s\n" % (base, sta, rst))
if base is None:
    print("no serial status"); sys.exit(2)

print("== phase 1: WebSocket connect/stream/disconnect ==")
ws_marks = []
for i in range(CYCLES):
    try:
        s = ws_open()
    except Exception as e:
        print("  cycle %d: ws_open failed: %s" % (i + 1, e))
        break
    got = ws_drain(s, 6)
    ws_close(s)
    h, sta, _ = heap(3.0)
    ws_marks.append(h)
    print("  cycle %d: streamed %6d B, heap after close = %s (ap_sta=%s)" % (i + 1, got, h, sta))

print("\n== phase 2: plain HTTP requests, no WebSocket ==")
http_marks = []
for i in range(CYCLES):
    n = sum(1 for _ in range(20) if http_get() > 0)
    h, sta, _ = heap(3.0)
    http_marks.append(h)
    print("  cycle %d: %2d/20 requests ok, heap = %s" % (i + 1, n, h))

print("\n== summary ==")
print("baseline           %s" % base)
if ws_marks:
    print("after WS cycles    %s   delta %+d over %d cycles (%+d per cycle)"
          % (ws_marks, ws_marks[-1] - base, len(ws_marks),
             (ws_marks[-1] - base) // max(1, len(ws_marks))))
if http_marks:
    d = http_marks[-1] - (ws_marks[-1] if ws_marks else base)
    print("after HTTP cycles  %s   delta %+d over %d cycles" % (http_marks, d, len(http_marks)))
ser.close()

verdict = []
if len(ws_marks) >= 2 and ws_marks[-1] < ws_marks[0] - 2000:
    verdict.append("WebSocket cycles leak (~%d B each)"
                   % ((ws_marks[0] - ws_marks[-1]) // (len(ws_marks) - 1)))
if len(http_marks) >= 2 and http_marks[-1] < http_marks[0] - 2000:
    verdict.append("HTTP cycles leak")
print("\n" + ("; ".join(verdict) if verdict else "no cumulative leak across cycles"))
