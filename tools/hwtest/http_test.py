"""HTTP/dashboard acceptance tests for ouispy-blesniff.

    python tools/hwtest/http_test.py

Requires this host to be joined to the device AP (ouispy-blesniff), reachable
at 192.168.4.1. If the device is also on USB, the final test reboots it and
checks the boot banner over serial. Covers:

  * empty / oversized POST bodies get a 400 instead of hanging the client
  * window+interval applied together, response echoes the clamped values
  * /api/ap rejects a bad SSID or password instead of silently no-opping
  * PAUSE -> RESUME preserves the ring (the RESUME-wipes-capture bug)
  * session.pcap downloads and parses as LINKTYPE 256
  * /api/reboot answers before restarting, and the boot banner is contiguous
"""
import json
import re
import socket
import struct
import sys
import time
import urllib.error
import urllib.request

HOST = "192.168.4.1"
BASE = "http://" + HOST
TIMEOUT = 8

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS  " if ok else "FAIL  ") + name + ((" :: " + str(detail)) if detail else ""))


def req(method, path, body=None, ctype="application/json", raw=False, timeout=TIMEOUT):
    """Returns (status, body). status 0 means the request never completed."""
    data = body if isinstance(body, (bytes, type(None))) else body.encode()
    r = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        r.add_header("Content-Type", ctype)
        r.add_header("Content-Length", str(len(data)))
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            payload = resp.read()
            return resp.status, (payload if raw else payload.decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        payload = e.read()
        return e.code, (payload if raw else payload.decode("utf-8", "replace"))
    except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
        return 0, "TIMEOUT/ERR: %s" % e


def jget(path):
    st, b = req("GET", path)
    try:
        return st, json.loads(b)
    except Exception:
        return st, None


# --------------------------------------------------------------------------
def main():
    st, body = req("GET", "/")
    check("H1 GET / serves the dashboard",
          st == 200 and "OUI-SPY BLESNIFF" in body, "status=%s len=%s" % (st, len(body)))
    check("H1b dead output-mode UI removed",
          'id="outPcap"' not in body and 'id="statOut"' not in body,
          "outPcap/statOut absent")

    st, cfg = jget("/api/config")
    check("H2 GET /api/config", st == 200 and cfg is not None, cfg)

    # ---- the hang fixes -------------------------------------------------
    st, b = req("POST", "/api/config", b"")
    check("H3 empty-body POST answers (was: client hang)", st == 400, "%s %s" % (st, b[:80]))

    st, b = req("POST", "/api/config", b"x" * 9000)
    check("H4 oversized POST answers (was: client hang)", st == 400, "%s %s" % (st, b[:80]))

    st, b = req("POST", "/api/config", b"{not json")
    check("H5 malformed JSON -> 400", st == 400, "%s %s" % (st, b[:80]))

    st, b = req("POST", "/api/ap", b"")
    check("H6 empty-body /api/ap answers", st == 400, "%s %s" % (st, b[:80]))

    # ---- window/interval applied together --------------------------------
    st, _ = req("POST", "/api/config", json.dumps({"scan_win": 30, "scan_int": 100}))
    st, b = req("POST", "/api/config", json.dumps({"scan_win": 200, "scan_int": 400}))
    try:
        got = json.loads(b)
    except Exception:
        got = {}
    check("H7 window+interval raised together (was: 100/400)",
          st == 200 and got.get("scan_win") == 200 and got.get("scan_int") == 400,
          "echo=%s" % b[:120])

    st, cfg2 = jget("/api/config")
    check("H7b persisted",
          cfg2 and cfg2.get("scan_win") == 200 and cfg2.get("scan_int") == 400,
          "scan_win=%s scan_int=%s" % (cfg2.get("scan_win"), cfg2.get("scan_int")) if cfg2 else cfg2)

    # Window above the coexistence cap must come back clamped to HALF the
    # interval -- never equal to it. window == interval starves SoftAP beacons
    # and knocked this very host off the AP mid-suite before the fix.
    st, b = req("POST", "/api/config", json.dumps({"scan_win": 900, "scan_int": 200}))
    got = json.loads(b) if st == 200 else {}
    check("H8 window capped at half the interval (was: = interval, AP starved)",
          got.get("scan_win") == 100 and got.get("scan_int") == 200, b[:120])

    # restore something sane
    req("POST", "/api/config", json.dumps({"scan_win": 30, "scan_int": 100}))

    # ---- AP validation ---------------------------------------------------
    st, b = req("POST", "/api/ap", json.dumps({"ssid": "test-ap", "pass": "short"}))
    check("H9 short AP password rejected (was: 200 + reboot)",
          st == 400 and "password" in b, "%s %s" % (st, b[:100]))

    st, b = req("POST", "/api/ap", json.dumps({"ssid": "", "pass": "longenough"}))
    check("H10 empty AP ssid rejected", st == 400 and "ssid" in b, "%s %s" % (st, b[:100]))

    # ---- session state machine ------------------------------------------
    st, b = req("GET", "/api/session.pcap")
    check("H11 download refused from IDLE", st == 409, "%s %s" % (st, b[:90]))

    st, b = req("POST", "/api/session/record")
    check("H12 record from IDLE", st == 200 and '"recording"' in b, "%s %s" % (st, b[:90]))

    st, b = req("POST", "/api/session/record")
    check("H13 record while RECORDING -> 409", st == 409, "%s %s" % (st, b[:110]))

    print("   capturing 6s...")
    time.sleep(6)

    st, b = req("POST", "/api/session/pause")
    check("H14 pause from RECORDING", st == 200 and '"paused"' in b, "%s %s" % (st, b[:90]))

    # Size before resume. There is no size endpoint, so stop->download->record
    # would perturb state; instead resume, capture more, stop and compare the
    # record count against a fresh short capture.
    st, b = req("POST", "/api/session/resume")
    check("H15 resume from PAUSED", st == 200 and '"recording"' in b, "%s %s" % (st, b[:90]))

    print("   capturing 6s more...")
    time.sleep(6)

    st, b = req("POST", "/api/session/stop")
    check("H16 stop from RECORDING", st == 200 and '"stopped"' in b, "%s %s" % (st, b[:90]))

    st, pcap = req("GET", "/api/session.pcap", raw=True, timeout=30)
    ok_dl = st == 200 and isinstance(pcap, bytes) and len(pcap) > 24
    check("H17 session.pcap downloads from STOPPED", ok_dl,
          "status=%s bytes=%s" % (st, len(pcap) if isinstance(pcap, bytes) else pcap))

    nrec = 0
    if ok_dl:
        magic, vmaj, vmin, tz, sig, snap, link = struct.unpack("<IHHiIII", pcap[:24])
        check("H18 pcap header: magic + LINKTYPE 256",
              magic == 0xA1B2C3D4 and link == 256,
              "magic=%08X ver=%d.%d linktype=%d snaplen=%d" % (magic, vmaj, vmin, link, snap))
        off, bad = 24, None
        while off + 16 <= len(pcap):
            ts, tus, incl, orig = struct.unpack("<IIII", pcap[off:off + 16])
            if incl != orig or incl == 0 or off + 16 + incl > len(pcap):
                bad = "record %d incl=%d orig=%d at %d" % (nrec, incl, orig, off)
                break
            rec = pcap[off + 16: off + 16 + incl]
            # 10 phdr + 4 AA + 2 LL hdr + 6 addr + advdata + 3 crc
            ll_len = rec[15] & 0x3F
            if 10 + 4 + 2 + ll_len + 3 != incl:
                bad = ("record %d LL length %d disagrees with incl_len %d"
                       % (nrec, ll_len, incl))
                break
            nrec += 1
            off += 16 + incl
        check("H19 every pcap record well-formed, LL length consistent",
              bad is None and nrec > 0, bad or "%d records, %d bytes" % (nrec, len(pcap)))

    # H20: the RESUME-preserves-ring check. A fresh record wipes the ring; a
    # short capture of the same length as ONE of the two halves above must
    # yield far fewer records than the paused-and-resumed session did.
    st, b = req("POST", "/api/session/record")
    check("H20 re-record from STOPPED", st == 200 and '"recording"' in b, "%s %s" % (st, b[:90]))
    print("   capturing 6s (single leg, for comparison)...")
    time.sleep(6)
    req("POST", "/api/session/stop")
    st, pcap2 = req("GET", "/api/session.pcap", raw=True, timeout=30)
    nrec2 = 0
    if st == 200 and len(pcap2) > 24:
        off = 24
        while off + 16 <= len(pcap2):
            ts, tus, incl, orig = struct.unpack("<IIII", pcap2[off:off + 16])
            if off + 16 + incl > len(pcap2):
                break
            nrec2 += 1
            off += 16 + incl
    # The paused/resumed session covered two 6s legs, so it should hold clearly
    # more than a single 6s leg. If RESUME had wiped the ring they would match.
    check("H21 RESUME preserved the ring (was: record wiped it)",
          nrec > nrec2 * 1.4,
          "two-leg session=%d records, single-leg=%d records" % (nrec, nrec2))

    # ---- reboot answers before restarting, and the banner is contiguous ---
    try:
        import serial, serial.tools.list_ports
        dev = next((p.device for p in serial.tools.list_ports.comports()
                    if p.hwid and "303A" in p.hwid.upper()), None)
    except Exception:
        dev = None

    ser = None
    if dev:
        try:
            ser = serial.Serial(dev, 115200, timeout=0.05)
            time.sleep(0.3)
            ser.reset_input_buffer()
        except Exception as e:
            print("   (serial not attachable: %s)" % e)
            ser = None

    t0 = time.time()
    st, b = req("POST", "/api/reboot", timeout=6)
    dt = time.time() - t0
    check("H22 /api/reboot replies before restarting (was: response lost)",
          st == 200, "status=%s in %.2fs %s" % (st, dt, b[:60]))

    if ser:
        lines, t_end = [], time.time() + 14
        while time.time() < t_end:
            raw = ser.readline()
            if raw:
                lines.append(raw.decode("utf-8", "replace").rstrip("\r\n"))
        ser.close()
        BANNER = set("█╔╗╚╝═║ ")
        ADV = re.compile(r"^\[Ch(\d+|\?) RSSI-?\d+dBm\]")
        bidx = [i for i, l in enumerate(lines)
                if l.strip() and set(l) <= BANNER and "█" in l]
        if bidx:
            lo, hi = min(bidx), max(bidx)
            # extend through the info block that follows the art
            tail = hi
            for i in range(hi + 1, min(len(lines), hi + 10)):
                if ADV.match(lines[i]):
                    break
                tail = i
            intruders = [lines[i] for i in range(lo, tail + 1) if ADV.match(lines[i])]
            check("H23 boot banner not split by advert lines",
                  not intruders,
                  "%d banner+info rows contiguous" % (tail - lo + 1) if not intruders
                  else "%d advert lines inside" % len(intruders))
            print("--- banner block ---")
            for i in range(lo, min(len(lines), tail + 3)):
                print("   |", lines[i][:130])
        else:
            check("H23 boot banner not split by advert lines", False,
                  "banner not seen in %d lines after reboot" % len(lines))

    print("\n==== %d/%d passed ====" % (sum(1 for _, ok, _ in results if ok), len(results)))
    for n, ok, d in results:
        if not ok:
            print("  FAILED:", n, "::", d)
    return 0 if all(ok for _, ok, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
