#include "config.h"

#include <Preferences.h>
#include <string.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

namespace config {

namespace {

constexpr const char* NS      = "blesniff";
constexpr const char* VERSION = "1.1.2";

Preferences prefs;
Config      cfg;

// cfg is read from the NimBLE host task (scan.cpp's onResult callback), the
// AsyncTCP task (HTTP handlers in web_dashboard.cpp), and the Arduino loop
// task (serial CMD:* handlers) -- three independent FreeRTOS tasks with no
// prior synchronization. This spinlock guards every in-memory read/write of
// cfg; it never wraps the blocking Preferences/NVS flash I/O in save()/load().
portMUX_TYPE g_cfg_mux = portMUX_INITIALIZER_UNLOCKED;

// Guards the single global `prefs` object's begin()/putX()/end() sequence in
// save(), which is reachable concurrently from the AsyncTCP task and the
// Arduino loop task. Preferences::begin() silently returns false (unchecked,
// same as upstream) if another task's session is still open rather than
// blocking, so without this a second concurrent save() would putX() against
// the first save()'s handle and then close it out from under it -- corrupting
// or silently dropping whichever fields hadn't been written yet. A real mutex
// (not the portMUX_TYPE spinlock above), since the NVS I/O it guards blocks.
SemaphoreHandle_t g_prefs_mutex = xSemaphoreCreateMutex();

// The last window value a caller explicitly asked for, before clamp() capped
// it against the interval in effect at the time. set_scan_interval() re-derives
// the stored window from this on every interval change, so a WINDOW command
// that got capped for coexistence is retried against a later, less
// restrictive interval instead of being silently stuck at the old cap.
uint16_t g_last_req_window = 0;

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

// Returns a snapshot copy rather than a reference to the live global: cfg is
// shared across three tasks (see g_cfg_mux above), so callers reading several
// fields off one get() -- e.g. `const auto& c = config::get();` -- get a
// consistent point-in-time view instead of racing a concurrent writer.
Config get() {
    portENTER_CRITICAL(&g_cfg_mux);
    Config c = cfg;
    portEXIT_CRITICAL(&g_cfg_mux);
    return c;
}

void load() {
    // Boot-time only, before any other task exists -- no lock needed here.
    apply_defaults();
    prefs.begin(NS, true);
    cfg.scan_window_ms   = prefs.getUShort("scan_win", cfg.scan_window_ms);
    cfg.scan_interval_ms = prefs.getUShort("scan_int", cfg.scan_interval_ms);
    cfg.ft_mask          = prefs.getUChar ("ftmask",   cfg.ft_mask);
    prefs.getString("ap_ssid", cfg.ap_ssid, sizeof(cfg.ap_ssid));
    prefs.getString("ap_pass", cfg.ap_pass, sizeof(cfg.ap_pass));
    prefs.end();
    clamp();
    g_last_req_window = cfg.scan_window_ms;
}

void save() {
    // clamp() and the snapshot run under the lock (fast, no I/O); the flash
    // write below does not -- portENTER_CRITICAL masks interrupts, and NVS
    // I/O can block/take a semaphore internally, which must never happen
    // with interrupts off.
    Config snapshot;
    portENTER_CRITICAL(&g_cfg_mux);
    clamp();
    snapshot = cfg;
    portEXIT_CRITICAL(&g_cfg_mux);

    // g_prefs_mutex serializes this against any other concurrent save() --
    // see its declaration above for why that matters for the shared `prefs`
    // object.
    xSemaphoreTake(g_prefs_mutex, portMAX_DELAY);
    prefs.begin(NS, false);
    prefs.putUShort("scan_win", snapshot.scan_window_ms);
    prefs.putUShort("scan_int", snapshot.scan_interval_ms);
    prefs.putUChar ("ftmask",   snapshot.ft_mask);
    prefs.putString("ap_ssid",  snapshot.ap_ssid);
    prefs.putString("ap_pass",  snapshot.ap_pass);
    prefs.end();
    xSemaphoreGive(g_prefs_mutex);
}

// Every setter below calls clamp() itself before releasing g_cfg_mux, not
// just inside save() afterward -- otherwise a concurrent get() in the gap
// between a setter's portEXIT_CRITICAL and save()'s own portENTER_CRITICAL
// could observe cfg in a state clamp() exists specifically to rule out (e.g.
// window > max_window_for(interval), or an entire filter gate zeroed).
// save() still re-clamps under its own lock too; that second pass is a
// cheap no-op once the setter has already normalized cfg.

void reset_defaults() {
    portENTER_CRITICAL(&g_cfg_mux);
    apply_defaults();
    clamp();
    g_last_req_window = cfg.scan_window_ms;
    portEXIT_CRITICAL(&g_cfg_mux);
    save();
}

void set_scan_window(uint16_t ms) {
    portENTER_CRITICAL(&g_cfg_mux);
    g_last_req_window  = ms;
    cfg.scan_window_ms = ms;
    clamp();
    portEXIT_CRITICAL(&g_cfg_mux);
    save();
}

void set_scan_interval(uint16_t ms) {
    portENTER_CRITICAL(&g_cfg_mux);
    cfg.scan_interval_ms = ms;
    // Re-derive window from the last explicitly requested value, not the
    // already-clamped stored one -- so WINDOW 150 (capped to 50 under
    // interval=100) followed by INTERVAL 400 restores 150 (now legal under
    // the new interval) instead of leaving window stuck at 50.
    cfg.scan_window_ms = g_last_req_window;
    clamp();
    portEXIT_CRITICAL(&g_cfg_mux);
    save();
}

void set_ftmask(uint8_t m) {
    portENTER_CRITICAL(&g_cfg_mux);
    cfg.ft_mask = m;
    clamp();
    portEXIT_CRITICAL(&g_cfg_mux);
    save();
}

void set_scan_params(uint16_t window_ms, uint16_t interval_ms) {
    portENTER_CRITICAL(&g_cfg_mux);
    g_last_req_window    = window_ms;
    cfg.scan_window_ms   = window_ms;
    cfg.scan_interval_ms = interval_ms;
    clamp();   // sees both new values together
    portEXIT_CRITICAL(&g_cfg_mux);
    save();
}

void set_ap(const char* ssid, const char* pass) {
    portENTER_CRITICAL(&g_cfg_mux);
    if (ssid && *ssid) strlcpy(cfg.ap_ssid, ssid, sizeof(cfg.ap_ssid));
    if (pass) {
        size_t l = strlen(pass);
        if (l >= 8 && l <= 63) strlcpy(cfg.ap_pass, pass, sizeof(cfg.ap_pass));
    }
    clamp();
    portEXIT_CRITICAL(&g_cfg_mux);
    save();
}

} // namespace config
