#pragma once

#include <Arduino.h>

namespace config {

// Filter mask bits — matched against per-advert traits at capture time.
// Advert type bits use the wire-level LE LL PDU type numbering.
constexpr uint8_t FT_ADV_IND       = 0x01;
constexpr uint8_t FT_ADV_DIRECT    = 0x02;
constexpr uint8_t FT_ADV_NONCONN   = 0x04;
constexpr uint8_t FT_SCAN_RSP      = 0x08;
constexpr uint8_t FT_ADV_SCAN_IND  = 0x10;
// Address-type gate (all-on default): drop random-address adverts when off, etc.
constexpr uint8_t FT_ADDR_PUBLIC   = 0x20;
constexpr uint8_t FT_ADDR_RANDOM   = 0x40;
// Reserved/spare
constexpr uint8_t FT_SPARE_7       = 0x80;

// The two independent gates. Every advert has exactly one PDU type and one
// address class, so a mask with no bits in either group would capture nothing
// at all -- clamp() treats an empty group as "no filter on that axis".
constexpr uint8_t FT_TYPE_BITS =
    FT_ADV_IND | FT_ADV_DIRECT | FT_ADV_NONCONN | FT_SCAN_RSP | FT_ADV_SCAN_IND;
constexpr uint8_t FT_ADDR_BITS = FT_ADDR_PUBLIC | FT_ADDR_RANDOM;

constexpr uint8_t FT_DEFAULT = FT_TYPE_BITS | FT_ADDR_BITS;

// The BLE scan and the SoftAP share one 2.4 GHz radio. A scan window that
// takes the whole interval starves SoftAP beacons and the dashboard goes
// unreachable -- recoverable only over serial or a BOOT-button factory reset.
// Verified on an XIAO ESP32-S3: 200/400 keeps the AP up, 200/200 kills it.
// So the window is capped at half the interval, never clamped up to equal it.
constexpr uint16_t MAX_WINDOW_PCT = 50;

inline uint16_t max_window_for(uint16_t interval_ms) {
    uint16_t w = (uint16_t)((uint32_t)interval_ms * MAX_WINDOW_PCT / 100);
    return w < 10 ? 10 : w;
}

// USB output is text-only (line summaries + CMD replies). PCAP binary
// capture lives on the dashboard exclusively -- GET /api/session.pcap.
struct Config {
    uint16_t scan_window_ms;   // 10..scan_interval_ms
    uint16_t scan_interval_ms; // 20..4000
    uint8_t  ft_mask;
    char     ap_ssid[33];
    char     ap_pass[64];
};

void        load();
void        save();
void        reset_defaults();
Config&     get();

void set_scan_window(uint16_t ms);
void set_scan_interval(uint16_t ms);
// Apply both at once. Setting them one at a time clamps window against the
// *old* interval, which silently loses a window increase that is only legal
// under the new interval (e.g. 30/100 -> 200/400 would land on 100/400).
void set_scan_params(uint16_t window_ms, uint16_t interval_ms);
void set_ftmask(uint8_t m);
void set_ap(const char* ssid, const char* pass);

const char* FW_VERSION();

} // namespace config
