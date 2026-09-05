#include <Arduino.h>
#include <Adafruit_NeoPixel.h>
#include <LittleFS.h>
#include <WiFi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_system.h>
#include <ctype.h>

#include "config.h"
#include "scan.h"
#include "pcap_stream.h"
#include "session_pcap.h"
#include "text_summary.h"
#include "web_dashboard.h"

namespace {

constexpr uint8_t  PIN_NEOPIXEL = 21;
constexpr uint8_t  PIN_BOOT     = 0;

Adafruit_NeoPixel pixel(1, PIN_NEOPIXEL, NEO_GRB + NEO_KHZ800);

enum class Fault { None, LittleFS, Wifi, Scan, Task };
volatile Fault g_fault = Fault::None;

const char* fault_name() {
    switch (g_fault) {
        case Fault::None:     return "none";
        case Fault::LittleFS: return "littlefs";
        case Fault::Wifi:     return "wifi";
        case Fault::Scan:     return "scan";
        case Fault::Task:     return "task";
    }
    return "?";
}

TaskHandle_t pcap_task_h = nullptr;
TaskHandle_t led_task_h  = nullptr;

volatile uint32_t last_advert_ms = 0;

void led_task(void*) {
    uint32_t last_pkt_seen = 0;
    uint32_t amber_until = 0;
    for (;;) {
        uint32_t now = millis();
        uint32_t r = 0, g = 0, b = 0;

        if (g_fault != Fault::None) {
            r = 40; g = 0; b = 0;
        } else {
            // Slow blue pulse — sniffer alive, scanning passively.
            float phase = (now % 2500) / 2500.0f;
            float pulse = 0.3f + 0.3f * sinf(phase * 6.2831853f);
            b = (uint8_t)(35 * pulse);
        }

        uint32_t pkt_ms = last_advert_ms;
        if (pkt_ms != last_pkt_seen) {
            last_pkt_seen = pkt_ms;
            // The old rate-limit here compared unsigned millis against a future
            // deadline, so it underflowed and was always true. Same behaviour,
            // without pretending to gate anything.
            amber_until = now + 20;
        }
        // Signed-difference form, not `now < amber_until`: near the millis()
        // wraparound (~49.7 days uptime) a plain unsigned compare can read
        // false for one iteration even though amber_until is genuinely still
        // in the future, skipping the flash. This form is correct across the
        // wraparound as long as the true difference fits in int32_t (it's at
        // most 20ms here).
        if ((int32_t)(amber_until - now) > 0) {
            r = 30; g = 20; b = 0;
        }

        pixel.setPixelColor(0, pixel.Color(r, g, b));
        pixel.show();
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

void pcap_writer_task(void*) {
    // USB output is text only. Full PCAP capture lives on the dashboard
    // (GET /api/session.pcap). session_pcap::append fills the download
    // buffer for every frame regardless of USB text emission.
    for (;;) {
        scan::Frame f;
        int drained = 0;
        while (drained < 16 && scan::pop_pcap(&f)) {
            last_advert_ms = millis();
            pcap_stream::write_frame_text(f);
            session_pcap::append(f);
            drained++;
        }
        vTaskDelay(pdMS_TO_TICKS(drained ? 2 : 10));
    }
}

// Why the last boot happened. Surfaced in the banner and CMD:STATUS so an
// unexpected reset (panic, watchdog, brownout) is visible instead of just
// looking like a device that quietly came back IDLE.
const char* reset_reason_name() {
    switch (esp_reset_reason()) {
        case ESP_RST_POWERON:   return "poweron";
        case ESP_RST_EXT:       return "external";
        case ESP_RST_SW:        return "software";
        case ESP_RST_PANIC:     return "panic";
        case ESP_RST_INT_WDT:   return "int_wdt";
        case ESP_RST_TASK_WDT:  return "task_wdt";
        case ESP_RST_WDT:       return "wdt";
        case ESP_RST_DEEPSLEEP: return "deepsleep";
        case ESP_RST_BROWNOUT:  return "brownout";
        case ESP_RST_SDIO:      return "sdio";
        default:                return "unknown";
    }
}

void print_banner() {
    Serial.println();
    Serial.println(F(" ██████╗ ██╗   ██╗██╗      ███████╗██████╗ ██╗   ██╗    ██████╗ ██╗     ███████╗███████╗███╗   ██╗██╗███████╗███████╗"));
    Serial.println(F("██╔═══██╗██║   ██║██║      ██╔════╝██╔══██╗╚██╗ ██╔╝    ██╔══██╗██║     ██╔════╝██╔════╝████╗  ██║██║██╔════╝██╔════╝"));
    Serial.println(F("██║   ██║██║   ██║██║█████╗███████╗██████╔╝ ╚████╔╝     ██████╔╝██║     █████╗  ███████╗██╔██╗ ██║██║█████╗  █████╗  "));
    Serial.println(F("██║   ██║██║   ██║██║╚════╝╚════██║██╔═══╝   ╚██╔╝      ██╔══██╗██║     ██╔══╝  ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  "));
    Serial.println(F("╚██████╔╝╚██████╔╝██║      ███████║██║        ██║       ██████╔╝███████╗███████╗███████║██║ ╚████║██║██║     ██║     "));
    Serial.println(F(" ╚═════╝  ╚═════╝ ╚═╝      ╚══════╝╚═╝        ╚═╝       ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     "));
    Serial.print(F("OUI-SPY BLESNIFF  fw="));
    Serial.print(config::FW_VERSION());
    Serial.print(F("  built="));
    Serial.print(F(__DATE__ " " __TIME__));
    Serial.println();
    Serial.print(F("Reset reason: ")); Serial.println(reset_reason_name());
    Serial.println(F("Passive receive only. Nothing is transmitted."));
    Serial.println(F("Session PCAP boots IDLE. POST /api/session/record (or click"));
    Serial.println(F("RECORD in the dashboard) to start capturing to the ring."));
    Serial.println();
}

String upper(const String& s) { String o = s; o.toUpperCase(); return o; }

// One write() per reply. HWCDC takes its tx mutex per write, so a single call
// is atomic against pcap_writer_task's advert lines -- but print() followed by
// println() is two calls, and an advert line could land in the gap and split
// the reply that scripts parse.
void reply_ok() { Serial.write("OK\n", 3); }

void reply_err(const char* m) {
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "ERR %s\n", m);
    if (n <= 0) return;
    if (n >= (int)sizeof(buf)) n = (int)sizeof(buf) - 1;
    Serial.write(buf, (size_t)n);
}

// config::get().ap_ssid is user-controlled (POST /api/ap) and reaches CMD:STATUS's
// JSON reply as a bare %s with no quoting. A stored '"' or control character (both
// legal after ArduinoJson decodes the POST body's JSON escapes) would otherwise
// terminate the string early or split the reply across physical serial lines.
void json_escape(const char* src, char* out, size_t out_sz) {
    size_t o = 0;
    for (const char* p = src; *p && o + 1 < out_sz; ++p) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') {
            if (o + 2 >= out_sz) break;
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c < 0x20) {
            if (o + 6 >= out_sz) break;
            o += snprintf(out + o, 7, "\\u%04x", c);
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = 0;
}

void handle_serial_cmd(const String& raw) {
    String line = raw; line.trim();
    if (!line.startsWith("CMD:") && !line.startsWith("cmd:")) return;
    String body = line.substring(4);
    body.trim();
    String U = upper(body);

    if (U == "STATUS") {
        // One snapshot, not four separate config::get() calls -- config.h's
        // own doc comment on get() says as much: a concurrent write landing
        // between separate calls could otherwise report a scan_win/scan_int
        // pairing (or an ap_ssid) that never actually coexisted in cfg.
        const config::Config c = config::get();
        IPAddress ip = WiFi.softAPIP();
        String apmac = WiFi.softAPmacAddress();
        char ssid_esc[33 * 6 + 1];   // worst case: every char becomes \u00XX
        json_escape(c.ap_ssid, ssid_esc, sizeof(ssid_esc));
        // One locked read for size/dropped/state together -- see
        // session_pcap::get_status()'s definition for why three separate
        // calls here could report a self-inconsistent composite.
        const session_pcap::Status sess = session_pcap::get_status();
        Serial.printf("{\"scan_win\":%u,\"scan_int\":%u,\"ftmask\":\"0x%02x\","
            "\"total\":%u,\"pps\":%u,\"drop_pcap\":%u,\"drop_dash\":%u,\"drop_ws\":%u,\"fw\":\"%s\","
            "\"ap_ssid\":\"%s\",\"ap_ip\":\"%s\",\"ap_mac\":\"%s\",\"ap_stations\":%u,"
            "\"session_bytes\":%u,\"session_cap\":%u,\"session_drop\":%u,"
            "\"state\":\"%s\",\"psram_free\":%u,\"heap_free\":%u,\"reset\":\"%s\",\"fault\":\"%s\"}\n",
            (unsigned)c.scan_window_ms,
            (unsigned)c.scan_interval_ms,
            (unsigned)c.ft_mask,
            (unsigned)scan::total_adverts(),
            (unsigned)scan::adverts_per_sec(),
            (unsigned)scan::dropped_pcap(),
            (unsigned)scan::dropped_dash(),
            (unsigned)web_dashboard::ws_dropped(),
            config::FW_VERSION(),
            ssid_esc, ip.toString().c_str(), apmac.c_str(),
            (unsigned)WiFi.softAPgetStationNum(),
            (unsigned)sess.size,
            (unsigned)session_pcap::capacity(),
            (unsigned)sess.dropped,
            session_pcap::state_name(sess.state),
            (unsigned)ESP.getFreePsram(),
            (unsigned)ESP.getFreeHeap(),
            reset_reason_name(),
            fault_name());
        return;
    }
    if (U == "VERSION") {
        Serial.printf("OUI-SPY BLESNIFF %s built %s %s\n", config::FW_VERSION(), __DATE__, __TIME__);
        return;
    }
    if (U.startsWith("MODE ")) {
        // Kept as a compatibility no-op. USB output is text only; PCAP
        // binary capture lives on the dashboard at /api/session.pcap.
        reply_ok();
        return;
    }
    if (U.startsWith("WINDOW ")) {
        int v = U.substring(7).toInt();
        if (v < 10 || v > 2000) { reply_err("bad window"); return; }
        config::set_scan_window((uint16_t)v);
        scan::apply_scan_params();
        // The window is capped at half the interval for Wi-Fi coexistence, so
        // say what was stored rather than a bare OK that hides the clamp. One
        // get() call, not two -- a second call here could race a concurrent
        // config write and print a value unrelated to what this command set.
        const uint16_t stored = config::get().scan_window_ms;
        if (stored != (uint16_t)v) {
            char buf[64];
            int n = snprintf(buf, sizeof(buf), "OK window=%u (capped for AP coexistence)\n",
                             (unsigned)stored);
            if (n > 0) Serial.write(buf, (size_t)(n < (int)sizeof(buf) ? n : (int)sizeof(buf) - 1));
        } else {
            reply_ok();
        }
        return;
    }
    if (U.startsWith("INTERVAL ")) {
        int v = U.substring(9).toInt();
        if (v < 20 || v > 4000) { reply_err("bad interval"); return; }
        // set_scan_interval() re-derives and re-clamps the stored window
        // against the new interval as a side effect (see config.cpp), so
        // report it the same way WINDOW reports its own clamp -- a bare OK
        // would silently hide a window change this command just caused.
        const uint16_t win_before = config::get().scan_window_ms;
        config::set_scan_interval((uint16_t)v);
        scan::apply_scan_params();
        const uint16_t win_after = config::get().scan_window_ms;
        if (win_after != win_before) {
            char buf[80];
            int n = snprintf(buf, sizeof(buf), "OK window=%u (recalculated for AP coexistence)\n",
                             (unsigned)win_after);
            if (n > 0) Serial.write(buf, (size_t)(n < (int)sizeof(buf) ? n : (int)sizeof(buf) - 1));
        } else {
            reply_ok();
        }
        return;
    }
    reply_err("unknown");
}

void serial_pump() {
    static String line;
    while (Serial.available()) {
        int c = Serial.read();
        if (c < 0) break;
        if (c == '\n' || c == '\r') {
            if (line.length()) { handle_serial_cmd(line); line = ""; }
        } else {
            if (line.length() < 200) line += (char)c;
        }
    }
}

void boot_button_poll() {
    static uint32_t held_since = 0;
    if (digitalRead(PIN_BOOT) == LOW) {
        if (held_since == 0) held_since = millis();
        else if (millis() - held_since > 1500) {
            config::reset_defaults();
            ESP.restart();
        }
    } else {
        held_since = 0;
    }
}

bool wifi_ap_start() {
    WiFi.mode(WIFI_AP);
    // BLE + Wi-Fi coexistence: NimBLE brings up the BT controller which
    // shares the 2.4 GHz radio. AsyncWebServer + softAP work fine alongside
    // NimBLE scan on ESP32-S3 as long as we don't pin either to an aggressive
    // channel. Channel 1 default is a reasonable choice.
    return WiFi.softAP(config::get().ap_ssid, config::get().ap_pass, 1, 0, 4);
}

} // namespace

void setup() {
    Serial.begin(115200);
    pinMode(PIN_BOOT, INPUT_PULLUP);
    pixel.begin();
    pixel.setPixelColor(0, 0);
    pixel.show();

    // Keep the first fault, not the last: each of these is checked
    // unconditionally, and overwriting g_fault on a later failure would hide
    // which subsystem actually failed first (often the root cause of the
    // ones after it).
    if (!LittleFS.begin(true) && g_fault == Fault::None) {
        g_fault = Fault::LittleFS;
    }

    config::load();

    if (!wifi_ap_start() && g_fault == Fault::None) {
        g_fault = Fault::Wifi;
    }

    session_pcap::init();
    web_dashboard::init();

    if (!scan::init() && g_fault == Fault::None) {
        g_fault = Fault::Scan;
    }

    // pcap_stream no longer needs init -- USB output is text-only, session
    // buffer for the dashboard is initialized separately.

    // Print the banner before pcap_writer_task exists. scan::init() has already
    // started filling the ring, so starting the writer first let advert lines
    // interleave with the multi-println banner.
    print_banner();

    // pcap_writer_task copies scan::Frame (~280B) into a stack local per pop;
    // 8KB is comfortable headroom.
    if (xTaskCreatePinnedToCore(&pcap_writer_task, "pcap_wr", 8192, nullptr, 5, &pcap_task_h, 0) != pdPASS) {
        if (g_fault == Fault::None) g_fault = Fault::Task;
        Serial.println(F("[boot] FATAL: failed to create pcap_writer_task -- capture pipeline is dead"));
    }
    if (xTaskCreatePinnedToCore(&led_task, "led", 2048, nullptr, 1, &led_task_h, 0) != pdPASS) {
        if (g_fault == Fault::None) g_fault = Fault::Task;
        Serial.println(F("[boot] FATAL: failed to create led_task"));
    }
}

void loop() {
    serial_pump();
    boot_button_poll();
    web_dashboard::tick();
    delay(20);
}
