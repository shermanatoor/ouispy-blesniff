# Wireshark integration

**PCAP capture is served by the on-device dashboard.** Point your browser at
`http://192.168.4.1` after joining the `ouispy-blesniff` / `sniffuntothem`
Wi-Fi, click **Save PCAP** on the toolbar, and open the downloaded file in
Wireshark.

The USB-CDC PCAP streaming path (previously `ouispy_blesniff_pipe.py` +
`ouispy_blesniff_extcap.py`) has been removed: ESP32-S3 Arduino USB CDC is
not reliable for high-rate binary streaming, and the dashboard path uses an
immutable PSRAM snapshot which parses cleanly regardless of capture rate.

USB CDC still emits human-readable text summaries (one line per advert) and
responds to `CMD:STATUS` / `CMD:VERSION` for scripting.

# Hardware acceptance tests

`tools/hwtest/` holds two scripts that exercise a flashed device end to end.
They need `pyserial` (bundled with PlatformIO).

```bash
python tools/hwtest/serial_test.py   # device on USB; ~15 s
python tools/hwtest/http_test.py     # host joined to ouispy-blesniff; ~40 s
```

`serial_test.py` checks the USB text interface: CMD replies land as single
intact lines, `CMD:STATUS` is one valid JSON object, and the pps counter holds
up under polling. `http_test.py` walks the dashboard API -- POST error paths,
window/interval clamping (including the Wi-Fi coexistence cap), AP credential
validation, the Record/Pause/Resume/Stop state machine, a PCAP download that
is parsed record by record, and finally `/api/reboot` with the serial port
held open to confirm the reply arrives and the boot banner is contiguous.

# Vendor identifier validation

`tools/validate_ids.py` cross-checks every OUI, Bluetooth SIG company ID and
16-bit service UUID in the dashboard `VENDORS` table and `mfr_shortname()`
against the live IEEE MA-L and Bluetooth SIG registries (cached in
`.ids-cache/`). Run it before editing either table; `--search` also lists
registry entries assigned to a vendor that the tables do not carry yet.

Entries are one of two kinds. **Registry** entries are assigned to the vendor
in the registries and the validator fails the build if one goes stale.
**Observed** entries come from field research on the vendor's hardware
(Detector OUI Database) and typically belong to the radio-module maker --
Espressif, Telink -- so they match other devices using the same module. The
validator reports these as `obs` and never fails them; do not prune them.

## Confidence tiers

`ouis` are registry-assigned to the vendor; `ouisBroad` are radio-module makers
and unattributed prefixes seen on the vendor's hardware. A `ouisBroad`-only
match renders as `FLOCK?` with a dashed border and does not count as a hit when
**Confident only** is ticked, because an Espressif or Liteon OUI is shared with
every unrelated device built on the same module.

# Host-side unit tests

`tools/hosttest/` builds a few `src/*.cpp` files' pure parsing logic against a
minimal Arduino stand-in (`tools/hosttest/stub/Arduino.h`) and runs them on the
host -- no board needed. Useful for anything that only touches buffers, not
peripherals. Requires a C++17 compiler (MinGW-w64 via `scoop install gcc`, or
any g++/clang++ on PATH).

```bash
g++ -std=c++17 -I tools/hosttest/stub -o tools/hosttest/test_text_summary tools/hosttest/test_text_summary.cpp
./tools/hosttest/test_text_summary
```

`test_text_summary.cpp` covers `text_summary.cpp`'s AD-structure parsing:
16/32/128-bit and Service-Data service UUIDs (including reduction to the short
form, non-reduction of a genuinely custom 128-bit UUID, and de-duplication
across encodings), and complete-vs-shortened local name precedence.
