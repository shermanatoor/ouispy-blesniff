"""Session ring wrap test for ouispy-blesniff.

    PLATFORMIO_BUILD_FLAGS=-DOUISPY_SESSION_CAP=65536 pio run -t upload
    python tools/hwtest/wrap_test.py [seconds]

Records long enough to overfill a small session ring several times over, then
downloads and parses the PCAP record by record. Proves the circular buffer:
records that straddle the physical wrap read back intact, the oldest records
were reclaimed (dropped > 0), timestamps stay monotonic, and the file size sits
just under the configured cap. Host must be joined to the device AP.
"""
import json
import struct
import sys
import time
import urllib.error
import urllib.request

BASE = "http://192.168.4.1"
SECS = float(sys.argv[1]) if len(sys.argv) > 1 else 45


def req(method, path, timeout=30):
    r = urllib.request.Request(BASE + path, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, ("NO RESPONSE: %s" % e).encode()


def status_ws():
    """One status frame off the WebSocket would be ideal; CMD:STATUS over serial
    is simpler. Use serial if available, else skip the cap/drop readout."""
    try:
        import serial, serial.tools.list_ports
        dev = next(p.device for p in serial.tools.list_ports.comports()
                   if "303A" in (p.hwid or "").upper())
        s = serial.Serial(dev, 115200, timeout=0.2)
        time.sleep(0.2)
        s.reset_input_buffer()
        s.write(b"CMD:STATUS\n"); s.flush()
        t_end = time.time() + 1.5
        while time.time() < t_end:
            l = s.readline().decode("utf-8", "replace").strip()
            if l.startswith("{"):
                s.close()
                return json.loads(l)
        s.close()
    except Exception:
        pass
    return None


fails = 0
def check(name, ok, detail=""):
    global fails
    fails += 0 if ok else 1
    print(("PASS  " if ok else "FAIL  ") + name + (" :: " + str(detail) if detail else ""))


st = status_ws()
cap = st.get("session_cap") if st else None
print("session_cap:", cap)

req("POST", "/api/session/stop")          # from whatever state; ignore result
st_, b = req("POST", "/api/session/record")
check("record", st_ == 200, b[:60])
print("recording %.0fs..." % SECS)
time.sleep(SECS)

st = status_ws()
if st:
    print("live: session_bytes=%s session_drop=%s state=%s"
          % (st.get("session_bytes"), st.get("session_drop"), st.get("state")))
    check("ring wrapped at least once (dropped > 0)", st.get("session_drop", 0) > 0,
          "session_drop=%s" % st.get("session_drop"))
    if cap:
        check("ring stays within cap", st.get("session_bytes", 0) <= cap,
              "%s <= %s" % (st.get("session_bytes"), cap))
        check("ring is nearly full (reclaim is lazy, not bulk)",
              st.get("session_bytes", 0) > cap * 0.95,
              "%.1f%% of cap" % (100.0 * st.get("session_bytes", 0) / cap))

st_, b = req("POST", "/api/session/stop")
check("stop", st_ == 200, b[:60])

st_, pcap = req("GET", "/api/session.pcap", timeout=60)
check("download", st_ == 200 and len(pcap) > 24, "status=%s bytes=%s" % (st_, len(pcap)))
if st_ != 200:
    print("cannot parse without a download -- is this host on the device AP?")
    sys.exit(1)

magic, vmaj, vmin, tz, sig, snap, link = struct.unpack("<IHHiIII", pcap[:24])
check("header", magic == 0xA1B2C3D4 and link == 256, "linktype=%d" % link)

off, n, bad, last_ts = 24, 0, None, 0
while off + 16 <= len(pcap):
    ts, tus, incl, orig = struct.unpack("<IIII", pcap[off:off + 16])
    if incl != orig or incl == 0 or off + 16 + incl > len(pcap):
        bad = "record %d incl=%d orig=%d at %d" % (n, incl, orig, off); break
    rec = pcap[off + 16: off + 16 + incl]
    aa = struct.unpack("<I", rec[10:14])[0]
    if aa != 0x8E89BED6:
        bad = "record %d: access address %08X (ring wrap corrupted a record?)" % (n, aa); break
    if 10 + 4 + 2 + (rec[15] & 0x3F) + 3 != incl:
        bad = "record %d: LL length disagrees with incl_len" % n; break
    t = ts * 1000000 + tus
    if t < last_ts:
        bad = "record %d: timestamp went backwards" % n; break
    last_ts = t
    n += 1
    off += 16 + incl
check("every record intact across wraps", bad is None and n > 0,
      bad or "%d records, %d bytes, no trailing partial" % (n, len(pcap)))
check("file ends on a record boundary", off == len(pcap), "off=%d len=%d" % (off, len(pcap)))
if cap:
    check("download size within cap", len(pcap) <= cap, "%d <= %d" % (len(pcap), cap))

req("POST", "/api/session/record"); req("POST", "/api/session/stop")   # leave a clean STOPPED
print("\n%s" % ("ALL PASS" if fails == 0 else "%d FAILED" % fails))
sys.exit(1 if fails else 0)
