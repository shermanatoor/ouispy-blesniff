#include "config.h"

#include <Preferences.h>
#include <string.h>

namespace config {

namespace {

constexpr const char* NS      = "blesniff";
constexpr const char* VERSION = "1.0.0";

Preferences prefs;
Config      cfg;

void apply_defaults() {
    // Leave ~70% of the 2.4 GHz radio for WiFi coexistence so the AP stays
    // reachable while we scan. window==interval starves SoftAP beacons.
    cfg.scan_window_ms   = 30;
    cfg.scan_interval_ms = 100;
    cfg.ft_mask          = FT_DEFAULT;
    strlcpy(cfg.ap_ssid, "ouispy-blesniff", sizeof(cfg.ap_ssid));
    strlcpy(cfg.ap_pass, "sniffuntothem",       sizeof(cfg.ap_pass));
}

void clamp() {
    if (cfg.scan_window_ms < 10)               cfg.scan_window_ms = 10;
    if (cfg.scan_window_ms > 2000)             cfg.scan_window_ms = 2000;
    if (cfg.scan_interval_ms < 20)             cfg.scan_interval_ms = 20;
    if (cfg.scan_interval_ms > 4000)           cfg.scan_interval_ms = 4000;
    // NOT `window = interval`: that is exactly the coexistence state that
    // starves SoftAP beacons and locks the dashboard out. Cap at half.
    const uint16_t maxw = max_window_for(cfg.scan_interval_ms);
    if (cfg.scan_window_ms > maxw) cfg.scan_window_ms = maxw;
    // Unchecking every box in one group used to leave a non-zero mask that
    // the address gate (or type gate) then rejected everything against, so
    // the dashboard just went silent. Empty group -> that gate wide open.
    if ((cfg.ft_mask & FT_TYPE_BITS) == 0)     cfg.ft_mask |= FT_TYPE_BITS;
    if ((cfg.ft_mask & FT_ADDR_BITS) == 0)     cfg.ft_mask |= FT_ADDR_BITS;
    if (strlen(cfg.ap_ssid) == 0)              strlcpy(cfg.ap_ssid, "ouispy-blesniff", sizeof(cfg.ap_ssid));
    size_t pl = strlen(cfg.ap_pass);
    if (pl < 8 || pl > 63)                     strlcpy(cfg.ap_pass, "sniffuntothem", sizeof(cfg.ap_pass));
}

} // namespace

const char* FW_VERSION() { return VERSION; }

Config& get() { return cfg; }

void load() {
    apply_defaults();
    prefs.begin(NS, true);
    cfg.scan_window_ms   = prefs.getUShort("scan_win", cfg.scan_window_ms);
    cfg.scan_interval_ms = prefs.getUShort("scan_int", cfg.scan_interval_ms);
    cfg.ft_mask          = prefs.getUChar ("ftmask",   cfg.ft_mask);
    prefs.getString("ap_ssid", cfg.ap_ssid, sizeof(cfg.ap_ssid));
    prefs.getString("ap_pass", cfg.ap_pass, sizeof(cfg.ap_pass));
    prefs.end();
    clamp();
}

void save() {
    clamp();
    prefs.begin(NS, false);
    prefs.putUShort("scan_win", cfg.scan_window_ms);
    prefs.putUShort("scan_int", cfg.scan_interval_ms);
    prefs.putUChar ("ftmask",   cfg.ft_mask);
    prefs.putString("ap_ssid",  cfg.ap_ssid);
    prefs.putString("ap_pass",  cfg.ap_pass);
    prefs.end();
}

void reset_defaults() {
    apply_defaults();
    save();
}

void set_scan_window(uint16_t ms)   { cfg.scan_window_ms = ms;   save(); }
void set_scan_interval(uint16_t ms) { cfg.scan_interval_ms = ms; save(); }
void set_ftmask(uint8_t m)          { cfg.ft_mask = m; save(); }   // save() normalizes

void set_scan_params(uint16_t window_ms, uint16_t interval_ms) {
    cfg.scan_window_ms   = window_ms;
    cfg.scan_interval_ms = interval_ms;
    save();   // clamp() inside save() now sees both new values together
}

void set_ap(const char* ssid, const char* pass) {
    if (ssid && *ssid) strlcpy(cfg.ap_ssid, ssid, sizeof(cfg.ap_ssid));
    if (pass) {
        size_t l = strlen(pass);
        if (l >= 8 && l <= 63) strlcpy(cfg.ap_pass, pass, sizeof(cfg.ap_pass));
    }
    save();
}

} // namespace config
