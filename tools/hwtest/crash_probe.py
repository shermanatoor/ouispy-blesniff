"""Hold the serial port open through a recording and catch whatever kills it.

    python tools/hwtest/crash_probe.py [seconds]

Waits for the device AP, POSTs /api/session/record, then reads the USB
console for the whole window, sampling CMD:STATUS every 5 s. Anything that
looks like a panic, watchdog, or reboot (Guru Meditation, Backtrace, rst:,
the boot banner) is printed with context, and the reset reason reported by
the rebooted firmware is shown at the end. Everything seen is saved to
crash_probe.log next to this script.
"""
import json
import os
import re
import socket
import sys
import time
import urllib.request

import serial
import serial.tools.list_ports

SECS = float(sys.argv[1]) if len(sys.argv) > 1 else 90
BASE = "http://192.168.4.1"
LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crash_probe.log")
PANIC = re.compile(r"Guru Meditation|Backtrace|abort\(\)|rst:0x|Task watchdog|Interrupt wdt|"
                   r"assert failed|LoadProhibited|StoreProhibited|IllegalInstruction|"
                   r"OUI-SPY BLESNIFF  fw=|Reset reason:", re.I)


def wait_ap(timeout=1200):
    end = time.time() + timeout
    while time.time() < end:
        k = socket.socket(); k.settimeout(1.5)
        try:
            k.connect(("192.168.4.1", 80)); k.close(); return True
        except Exception:
            pass
        finally:
            try: k.close()
            except Exception: pass
        time.sleep(1)
    return False


def post(path):
    try:
        with urllib.request.urlopen(urllib.request.Request(BASE + path, method="POST"), timeout=8) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


dev = next(p.device for p in serial.tools.list_ports.comports() if "303A" in (p.hwid or "").upper())
ser = serial.Serial(dev, 115200, timeout=0.05)
time.sleep(0.3)
ser.reset_input_buffer()
log = open(LOG, "w", encoding="utf-8")

print("waiting for AP...")
if not wait_ap():
    print("AP never reachable"); sys.exit(2)
st, body = post("/api/session/record")
print("record:", st, body)
t0 = time.time()
next_status = t0 + 5
events, lines = [], 0
last_status = None

while time.time() - t0 < SECS:
    if time.time() >= next_status:
        ser.write(b"CMD:STATUS\n"); ser.flush()
        next_status += 5
    raw = ser.readline()
    if not raw:
        continue
    l = raw.decode("utf-8", "replace").rstrip("\r\n")
    lines += 1
    log.write("%7.2f %s\n" % (time.time() - t0, l))
    if l.startswith("{"):
        try:
            d = json.loads(l)
            last_status = d
            print("t=%5.1fs state=%-9s bytes=%6s drop=%5s heap=%6s ap_sta=%s reset=%s"
                  % (time.time() - t0, d.get("state"), d.get("session_bytes"), d.get("session_drop"),
                     d.get("heap_free"), d.get("ap_stations"), d.get("reset")), flush=True)
        except Exception:
            pass
    elif PANIC.search(l):
        events.append((time.time() - t0, l))
        print("!! t=%5.1fs %s" % (time.time() - t0, l[:160]), flush=True)

ser.close(); log.close()
post("/api/session/stop")
print("\n%d serial lines logged to %s" % (lines, LOG))
if events:
    print("EVENTS:")
    for t, l in events:
        print("  t=%5.1fs %s" % (t, l[:200]))
else:
    print("no panic/reboot markers seen")
if last_status:
    print("last status: state=%s reset=%s" % (last_status.get("state"), last_status.get("reset")))
