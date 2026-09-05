# OUI-SPY BLESNIFF

Passive **BLE advertising** sniffer for the **Seeed Studio XIAO ESP32-S3**.

Sister firmware to [ouispy-pcap](https://github.com/colonelpanichacks/ouispy-pcap), same UX and flow but pointed at the 2.4&nbsp;GHz BLE advertising channels (37 / 38 / 39) instead of Wi-Fi 802.11.

> **Advertisements only.** The ESP32 radio only exposes BLE advertising events through its Bluetooth stack. Connected-device pairing traffic, encryption negotiation, and post-connection PDUs are NOT captured — for that you need an nRF52 sniffer or Ubertooth.
>
> What you *do* get: beacons, iBeacons, Eddystone, scan requests / responses, wearables broadcasting, AirTags, Meta glasses probes, Ring doorbell adverts, drone Remote ID adverts — everything on air on 37/38/39 with RSSI, address type, name, service UUIDs, manufacturer data.

---

## This fork

[shermanatoor/ouispy-blesniff](https://github.com/shermanatoor/ouispy-blesniff), forked from [colonelpanichacks/ouispy-blesniff](https://github.com/colonelpanichacks/ouispy-blesniff) — which remains the upstream project and the one distributed through OUI-Spy Unified Blue (see **Flash it** below).

Since forking: a hardware-verified pass fixing 20+ correctness bugs (a RESUME that silently wiped the capture, POST requests that could hang the client, a scan-window setting that could lock the dashboard off its own Wi-Fi), a rewrite of the session PCAP buffer to a true circular ring (no more multi-second stalls when it fills), confidence-tiered vendor detection (a widened Flock Safety dataset, but tagged `FLOCK?` rather than `FLOCK` when the only match is a radio-module OUI shared with unrelated hardware, not Flock's own), and every vendor OUI / company ID / service UUID checked against the live IEEE and Bluetooth SIG registries (`tools/validate_ids.py`). Full history in the [merged pull requests](https://github.com/shermanatoor/ouispy-blesniff/pulls?q=is%3Apr+is%3Amerged).

---

## Feature checklist

- NimBLE passive scan across 37/38/39, complete PDU capture with RSSI
- **USB-CDC text summary** — human-readable one-liner per advert (scriptable)
- **On-device dashboard** on `ouispy-blesniff` / `sniffuntothem` at `192.168.4.1` — live advert table, filter chips, session PCAP download (Wireshark-ready `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` / 256)
- **Chip filters**: advertising type, traits (name-present / mfr-data / service-data), vendor identify against a validated OUI/company-ID/service-UUID/name-pattern database (RING, AXON, FLOCK SAFETY, DJI, PARROT, SKYDIO, META/RAY-BAN). Matches come in two tiers: a registry-assigned identifier renders a confident tag (`FLOCK`), a radio-module-only match (an OUI shared with unrelated hardware built on the same part) renders `FLOCK?` and a **Confident only** toggle can drop those entirely. The ESP32 HCI advertising report only exposes ADV_IND / ADV_DIRECT / ADV_NONCONN / ADV_SCAN / SCAN_RSP, so the SCAN_REQ and CONNECT_REQ chips are present for completeness and stay at zero on this hardware; EXTENDED catches any advert type the firmware cannot map to a legacy PDU type
- **Server-side PSRAM session buffer** (tries 6 MB, falls back to 4 MB, then 2 MB — auto-selected at boot) with an explicit **Record / Pause / Stop / Save** state machine on the dashboard. Boots IDLE; capture only begins after you click RECORD. Download via `GET /api/session.pcap` is enabled from STOPPED only.
- Configurable scan window / interval from the dashboard, filters persist to NVS. The BLE scan and the SoftAP share one 2.4 GHz radio, so the window is capped at half the interval — a window that takes the whole interval starves the AP beacons and the dashboard becomes unreachable until you factory-reset from the BOOT button or serial

---

## Flash it

Included as **Mode 5** (or whichever slot follows PCAP) in the OUI-SPY Unified Blue **Dev** channel:

**https://colonelpanichacks.github.io/oui-spy-unified-blue/**

Pick **Dev / Experimental**, click **Connect & Flash**. That channel builds from upstream (colonelpanichacks) — to run this fork's fixes before they're merged back, build from this repo locally:

```bash
pio run -e seeed_xiao_esp32s3 -t upload
pio device monitor -b 115200
```

---

## Wireshark integration

Join the `ouispy-blesniff` / `sniffuntothem` Wi-Fi, open `http://192.168.4.1`, click **RECORD** on the session control strip to start capturing, **STOP** when you're done, then **SAVE PCAP**. The download is `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` (256) so Wireshark keeps channel + RSSI.

The session state machine has four states — IDLE (boot), RECORDING (buffering into the PSRAM ring), PAUSED (ring preserved, resumable), STOPPED (ring finalized, download enabled). Clicking RECORD from STOPPED wipes the ring and starts fresh. `POST /api/session/{record,pause,resume,stop}` drive it from a shell; illegal transitions return HTTP 409.

The USB-CDC PCAP binary streaming path has been removed — ESP32-S3 Arduino USB CDC is not reliable for high-rate binary streaming, and the dashboard download parses cleanly regardless of capture rate. See `tools/README.md`.

---

## Serial command protocol

Newline-terminated ASCII, prefix `CMD:`.

| Command | Effect |
|---|---|
| `CMD:WINDOW <ms>` | Set BLE scan window (10-2000, capped at half the interval) |
| `CMD:INTERVAL <ms>` | Set BLE scan interval (20-4000) |
| `CMD:STATUS` | Print device state as one JSON line |
| `CMD:VERSION` | Firmware version string |

---

## Hardware

**Board:** Seeed Studio XIAO ESP32-S3

| Pin | Function |
|---|---|
| GPIO 3 | Piezo buzzer (unused -- firmware never drives it) |
| GPIO 21 | User LED (inverted logic — LOW = ON) |
| GPIO 0 | BOOT button |

---

## Credits

- **[colonelpanichacks](https://github.com/colonelpanichacks)** — original author of OUI-SPY BLESNIFF, its sister [ouispy-pcap](https://github.com/colonelpanichacks/ouispy-pcap), the [OUI-Spy Unified Blue](https://colonelpanichacks.github.io/oui-spy-unified-blue/) distribution channel, and the [ouispy-detector](https://github.com/colonelpanichacks/ouispy-detector) OUI database this fork's vendor identification was originally seeded from.
- **[lukeswitz/oui-spy-unified-blue](https://github.com/lukeswitz/oui-spy-unified-blue)** — source of the expanded Flock Safety detection dataset (OUIs, company ID, service UUIDs, name patterns), which in turn credits colonelpanichacks/flock-you, zmattmanz/flock-detection, dougborg/AirHound, and VirtuallyScott/flock-you.
- **IEEE Registration Authority** (MA-L / OUI assignments) and the **[Bluetooth SIG](https://www.bluetooth.com/specifications/assigned-numbers/)** (company identifiers, member service UUIDs) — the public assigned-numbers registries this fork's vendor identification is checked against (`tools/validate_ids.py`).
- Built on **[h2zero/NimBLE-Arduino](https://github.com/h2zero/NimBLE-Arduino)**, **[mathieucarbou/ESPAsyncWebServer](https://github.com/mathieucarbou/ESPAsyncWebServer)** (+ its [AsyncTCP](https://github.com/mathieucarbou/AsyncTCP)), **[bblanchon/ArduinoJson](https://github.com/bblanchon/ArduinoJson)**, and **[adafruit/Adafruit_NeoPixel](https://github.com/adafruit/Adafruit_NeoPixel)**.

---

## License

MIT
