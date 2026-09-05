"""Serial-side acceptance tests for ouispy-blesniff.

    python tools/hwtest/serial_test.py

Needs the device on USB; no Wi-Fi required. Verifies CMD replies arrive as
whole single lines, CMD:STATUS emits one valid JSON object, pps survives
repeated CMD:STATUS polling, and advert summary lines parse.

T1 (boot banner contiguity) can only pass if the port is open while the
device boots -- USB CDC drops output when no host is attached. In practice
that means http_test.py's reboot step; expect T1 to report "missed the boot
window" when run standalone.
"""
import json
import re
import sys
import time

import serial
import serial.tools.list_ports

PORT_HINT = "303A"          # Espressif VID
BAUD = 115200


def find_port(timeout=25.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for p in serial.tools.list_ports.comports():
            if p.hwid and PORT_HINT in p.hwid.upper():
                return p.device
        time.sleep(0.1)
    return None


def open_port(dev, timeout=25.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            return serial.Serial(dev, BAUD, timeout=0.2)
        except Exception:
            time.sleep(0.15)
    return None


BANNER_CHARS = set("█╔╗╚╝═║░▒▓ ")
ADVERT_RE = re.compile(r"^\[Ch(\d+|\?) RSSI(-?\d+)dBm\] (\S+) (\S+?):([0-9a-f:]{17})")

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS  " if ok else "FAIL  ") + name + ((" :: " + detail) if detail else ""))


def main():
    dev = find_port()
    if not dev:
        print("no Espressif serial port found")
        return 2
    print("port:", dev)
    ser = open_port(dev)
    if not ser:
        print("could not open", dev)
        return 2

    # ---------------- collect the boot window ----------------
    boot = []
    t_end = time.time() + 12.0
    while time.time() < t_end:
        raw = ser.readline()
        if not raw:
            continue
        boot.append(raw.decode("utf-8", "replace").rstrip("\r\n"))
    boot_txt = "\n".join(boot)
    print("--- boot capture: %d lines ---" % len(boot))
    for l in boot[:40]:
        print("   |", l)
    if len(boot) > 40:
        print("   | ... %d more" % (len(boot) - 40))

    # T1: banner integrity -- no advert line inside the banner block
    banner_idx = [i for i, l in enumerate(boot)
                  if l.strip() and set(l) <= BANNER_CHARS and "█" in l]
    if banner_idx:
        lo, hi = min(banner_idx), max(banner_idx)
        intruders = [boot[i] for i in range(lo, hi + 1) if ADVERT_RE.match(boot[i])]
        check("T1 banner not split by advert lines",
              not intruders,
              "%d advert line(s) inside banner rows %d-%d" % (len(intruders), lo, hi)
              if intruders else "%d banner rows contiguous" % len(banner_idx))
    else:
        check("T1 banner not split by advert lines", False,
              "banner not captured (missed the boot window)")

    # T2: advert text lines parse
    adverts = [l for l in boot if ADVERT_RE.match(l)]
    check("T2 advert summary lines parse", len(adverts) > 0,
          "%d advert lines, e.g. %s" % (len(adverts), adverts[0] if adverts else "-"))

    # T3: no line is a mangled splice (an advert line embedded mid-line)
    spliced = [l for l in boot if "[Ch" in l and not l.startswith("[Ch")]
    check("T3 no spliced serial output", not spliced,
          (spliced[0][:100] if spliced else "clean"))

    # ---------------- command tests ----------------
    def cmd(text, wait=1.2):
        ser.reset_input_buffer()
        ser.write((text + "\n").encode())
        ser.flush()
        out, t_end = [], time.time() + wait
        while time.time() < t_end:
            raw = ser.readline()
            if raw:
                out.append(raw.decode("utf-8", "replace").rstrip("\r\n"))
        return out

    # T4: CMD:VERSION -- one whole line, not split
    got = cmd("CMD:VERSION")
    vers = [l for l in got if l.startswith("OUI-SPY BLESNIFF")]
    check("T4 CMD:VERSION single intact line", len(vers) == 1,
          vers[0] if vers else repr(got[:4]))

    # T5: CMD:STATUS -- exactly one line that is valid JSON
    got = cmd("CMD:STATUS")
    js = [l for l in got if l.startswith("{")]
    parsed, err = None, ""
    if len(js) == 1:
        try:
            parsed = json.loads(js[0])
        except Exception as e:
            err = str(e)
    check("T5 CMD:STATUS one valid JSON line", parsed is not None,
          err or (repr(js[:2]) if parsed is None else "keys=%d" % len(parsed)))
    if parsed:
        print("   status:", json.dumps(parsed, indent=None)[:400])
        check("T5b boots in IDLE", parsed.get("state") == "idle",
              "state=%r" % parsed.get("state"))

    # T6: bad WINDOW -> single intact ERR line
    got = cmd("CMD:WINDOW 5")
    errs = [l for l in got if l.startswith("ERR ")]
    check("T6 CMD:WINDOW 5 rejected on one line",
          errs == ["ERR bad window"], repr(got[:4]))

    # T7: unknown command -> single intact ERR line
    got = cmd("CMD:NOSUCHTHING")
    errs = [l for l in got if l.startswith("ERR ")]
    check("T7 unknown command rejected on one line",
          errs == ["ERR unknown"], repr(got[:4]))

    # T8: valid WINDOW -> OK on its own line
    got = cmd("CMD:WINDOW 40")
    oks = [l for l in got if l.strip() == "OK"]
    check("T8 CMD:WINDOW 40 accepted on one line", len(oks) == 1, repr(got[:4]))

    # T9: pps survives repeated CMD:STATUS polling (the atomics fix). Poll
    # faster than 1 Hz; before the fix each poll stole the window and the
    # reported pps collapsed to 0.
    pps_seen, totals = [], []
    for _ in range(10):
        got = cmd("CMD:STATUS", wait=0.55)
        js = [l for l in got if l.startswith("{")]
        if js:
            try:
                d = json.loads(js[0])
                pps_seen.append(d.get("pps"))
                totals.append(d.get("total"))
            except Exception:
                pass
    advancing = len(totals) >= 2 and totals[-1] > totals[0]
    check("T9 adverts still arriving under polling", advancing,
          "total %s -> %s" % (totals[0] if totals else "-", totals[-1] if totals else "-"))
    check("T9b pps non-zero while polling at ~2 Hz",
          any(p for p in pps_seen if p), "pps samples=%s" % pps_seen)

    # T10: window change persisted and clamped sanely
    got = cmd("CMD:STATUS")
    js = [l for l in got if l.startswith("{")]
    if js:
        d = json.loads(js[0])
        check("T10 CMD:WINDOW 40 took effect", d.get("scan_win") == 40,
              "scan_win=%s scan_int=%s" % (d.get("scan_win"), d.get("scan_int")))
        print("   session_cap=%s psram_free=%s heap_free=%s"
              % (d.get("session_cap"), d.get("psram_free"), d.get("heap_free")))

    ser.close()

    print("\n==== %d/%d passed ====" % (sum(1 for _, ok, _ in results if ok), len(results)))
    return 0 if all(ok for _, ok, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
