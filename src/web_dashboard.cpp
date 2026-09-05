#include "web_dashboard.h"
#include "scan.h"
#include "config.h"
#include "dashboard_html.h"
#include "text_summary.h"
#include "pcap_stream.h"
#include "session_pcap.h"

#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

namespace web_dashboard {

namespace {

AsyncWebServer   server(80);
AsyncWebSocket   ws("/ws");
TaskHandle_t     dash_task_h = nullptr;
uint32_t         boot_ms = 0;

// Adverts that made it off the ring but were thrown away because no client
// could accept the batch. Written and read from the dashboard task only.
uint32_t         g_ws_dropped = 0;

// Deferred restart deadline in millis(), 0 when disarmed. ESP.restart() used to
// run straight from the request callback after a delay(200): that blocks the
// AsyncTCP task and tears the stack down while the response is still being
// flushed, so the client often never saw its 200. tick() runs it from loop()
// instead, once AsyncTCP has had a chance to send.
volatile uint32_t g_restart_at = 0;

void schedule_restart(uint32_t in_ms) {
    uint32_t at = millis() + in_ms;
    g_restart_at = at ? at : 1;      // 0 means "disarmed"
}

size_t append_pkt_json(const scan::Frame& f, char* out, size_t cap) {
    char addr[18];
    text_summary::format_addr(f.addr, addr);
    char name[32] = {0};
    text_summary::extract_name(f, name, sizeof(name));
    char svc[80]; svc[0] = 0;
    text_summary::extract_service_uuids(f, svc, sizeof(svc));
    uint16_t mfr = text_summary::manufacturer_id(f);
    uint8_t  tr  = text_summary::traits(f);

    StaticJsonDocument<512> doc;
    doc["i"] = f.idx;
    doc["t"] = (uint32_t)(millis() - boot_ms);
    doc["c"] = (int)(f.channel <= 39 ? f.channel : -1);
    doc["r"] = (int)f.rssi;
    if (f.tx_power != INT8_MIN) doc["x"] = (int)f.tx_power;
    doc["y"] = text_summary::ll_type_name(f.ll_pdu_type);
    doc["a"] = text_summary::addr_type_short(f.addr_type);
    doc["m"] = addr;
    doc["l"] = f.payload_len;
    doc["f"] = tr;                                   // traits bitfield
    if (name[0]) doc["n"] = name;
    if (svc[0])  doc["s"] = svc;
    if (mfr != 0xFFFF) {
        char mbuf[16];
        snprintf(mbuf, sizeof(mbuf), "%04X", mfr);
        doc["u"] = mbuf;                             // mfr id hex
        doc["v"] = text_summary::mfr_shortname(mfr); // mfr shortname
    }

    // One pass straight into the batch. serializeJson(doc, void*, size) does
    // not NUL-terminate and truncates at `cap`, so n == cap is ambiguous
    // (exact fit or cut short) -- treat it as "did not fit"; the caller
    // flushes and retries into a fresh batch where it cannot be ambiguous.
    // This replaced measureJson() + serializeJson(): two full walks per advert.
    const size_t n = serializeJson(doc, out, cap);
    return (n == 0 || n >= cap) ? 0 : n;
}

void send_status() {
    if (ws.count() == 0) return;
    StaticJsonDocument<512> doc;
    doc["type"] = "status";
    doc["uptime"] = (uint32_t)((millis() - boot_ms) / 1000);
    doc["pps"]    = scan::adverts_per_sec();
    doc["total"]  = scan::total_adverts();
    doc["dropped_pcap"] = scan::dropped_pcap();
    doc["dropped_dash"] = scan::dropped_dash();
    doc["dropped_ws"]   = g_ws_dropped;
    doc["session_bytes"] = (uint32_t)session_pcap::size();
    doc["session_cap"]   = (uint32_t)session_pcap::capacity();
    doc["session_drop"]  = (uint32_t)session_pcap::dropped();
    doc["state"]         = session_pcap::state_name();
    doc["psram_free"]    = (uint32_t)ESP.getFreePsram();
    doc["heap_free"]     = (uint32_t)ESP.getFreeHeap();
    doc["fw"] = config::FW_VERSION();

    char buf[512];
    size_t n = serializeJson(doc, buf, sizeof(buf));
    // Same guard as the packet batches: pushing into a full client queue
    // makes AsyncWebSocket drop the message or the client, and a status tick
    // is the least important thing to force through.
    if (ws.availableForWriteAll()) ws.textAll(buf, n);
}

static constexpr size_t BATCH_CAP        = 8192;
static constexpr size_t BATCH_FLUSH_WATER = 6144;
static constexpr uint32_t BATCH_TICK_MS  = 30;
static constexpr int MAX_DRAIN_PER_TICK  = 120;

void flush_batch(char* buf, size_t& pos, uint16_t& count) {
    if (count == 0) return;
    buf[pos++] = ']';
    buf[pos++] = '}';
    if (ws.count() > 0) {
        if (ws.availableForWriteAll()) {
            ws.textAll(buf, pos);
        } else {
            // Client queue full. These adverts are gone for the dashboard --
            // say so instead of pretending the drop counters cover it.
            g_ws_dropped += count;
        }
    }
    pos = 0;
    count = 0;
}

void begin_batch(char* buf, size_t& pos) {
    memcpy(buf, "{\"type\":\"pkts\",\"p\":[", 20);
    pos = 20;
}

void dashboard_task(void*) {
    uint32_t last_status = 0;
    uint32_t last_flush  = 0;
    static char batch[BATCH_CAP];
    size_t pos = 0;
    uint16_t count = 0;
    begin_batch(batch, pos);

    // A frame popped off the ring but not yet serialized, because it did not
    // fit in the batch being built. It survives across iterations so a full
    // batch costs one extra flush instead of a silently discarded advert.
    scan::Frame carry;
    bool carried = false;

    for (;;) {
        int drained = 0;
        while (drained < MAX_DRAIN_PER_TICK) {
            if (!carried) {
                if (!scan::pop_dashboard(&carry)) break;
                carried = true;
            }
            // Reserve the separator plus the two closing bytes ("]}") that
            // flush_batch appends, so the batch can always be terminated.
            const size_t sep   = (count > 0) ? 1 : 0;
            const size_t fixed = pos + sep + 2;
            const size_t avail = (fixed < BATCH_CAP) ? (BATCH_CAP - fixed) : 0;
            const size_t n = avail ? append_pkt_json(carry, batch + pos + sep, avail) : 0;
            if (n == 0) {
                // Will never fit in an empty batch, so drop it rather than
                // spin forever on the same frame.
                if (count == 0) { carried = false; drained++; continue; }
                break;                       // flush below, retry next pass
            }
            if (sep) batch[pos] = ',';
            pos += sep + n;
            count++;
            drained++;
            carried = false;
            if (pos >= BATCH_FLUSH_WATER) break;
        }

        uint32_t now = millis();
        bool tick_expired = (now - last_flush) >= BATCH_TICK_MS;
        // `carried` here means the batch is too full for the next frame, so
        // flush now regardless of the tick.
        if (count > 0 && (tick_expired || carried || pos >= BATCH_FLUSH_WATER)) {
            flush_batch(batch, pos, count);
            begin_batch(batch, pos);
            last_flush = now;
        }

        if (now - last_status > 1000) {
            send_status();
            ws.cleanupClients();
            last_status = now;
        }
        vTaskDelay(pdMS_TO_TICKS(drained >= MAX_DRAIN_PER_TICK ? 2 : 20));
    }
}

void handle_get_config(AsyncWebServerRequest* req) {
    StaticJsonDocument<512> doc;
    const auto& c = config::get();
    doc["scan_win"] = c.scan_window_ms;
    doc["scan_int"] = c.scan_interval_ms;
    doc["ftmask"]   = c.ft_mask;
    doc["ap_ssid"]  = c.ap_ssid;
    doc["ap_pass"]  = c.ap_pass;
    String body;
    serializeJson(doc, body);
    req->send(200, "application/json", body);
}

// JSON POST bodies arrive in chunks, stashed in req->_tempObject (freed by
// ~AsyncWebServerRequest). The buffer is one byte longer than the body and
// zero-filled, so it is always a valid NUL-terminated string: this fork of
// AsyncWebServerRequest has no "bytes received" field, and the terminator is
// what makes a short or truncated body fail as invalid JSON rather than get
// parsed out of uninitialized heap.
//
// The reply is sent from onRequest, never from this callback. ESPAsyncWebServer
// always invokes onRequest once a request completes, but invokes the body
// callback only when there *is* a body -- replying from the body callback left
// an empty or over-long POST with no response at all, hanging the client until
// it timed out.
constexpr size_t MAX_BODY = 8192;

void accumulate_body(AsyncWebServerRequest* req, uint8_t* data, size_t len,
                     size_t index, size_t total) {
    if (total == 0 || total > MAX_BODY) return;
    if (index > total || len > total - index) return;   // malformed / over-long chunk
    if (index == 0 && req->_tempObject == nullptr) {
        req->_tempObject = calloc(total + 1, 1);
    }
    if (req->_tempObject == nullptr) return;
    memcpy((uint8_t*)req->_tempObject + index, data, len);
}

// Returns the accumulated body as a NUL-terminated string, or nullptr after
// replying 400 when the request carried no body or an over-long one.
const char* body_or_fail(AsyncWebServerRequest* req) {
    if (req->_tempObject == nullptr) {
        req->send(400, "application/json", "{\"error\":\"empty or oversized body\"}");
        return nullptr;
    }
    return (const char*)req->_tempObject;
}

void handle_post_config(AsyncWebServerRequest* req) {
    const char* body = body_or_fail(req);
    if (!body) return;

    StaticJsonDocument<640> doc;
    DeserializationError err = deserializeJson(doc, body);
    if (err) { req->send(400, "application/json", "{\"error\":\"json\"}"); return; }

    // Window and interval have to be applied together. Applying them one at a
    // time clamps the new window against the *old* interval, which silently
    // swallows a window increase: 30/100 -> 200/400 would land on 100/400.
    const bool has_win = doc.containsKey("scan_win");
    const bool has_int = doc.containsKey("scan_int");
    if (has_win || has_int) {
        uint16_t win = has_win ? (uint16_t)doc["scan_win"] : config::get().scan_window_ms;
        uint16_t itv = has_int ? (uint16_t)doc["scan_int"] : config::get().scan_interval_ms;
        if (win != config::get().scan_window_ms || itv != config::get().scan_interval_ms) {
            config::set_scan_params(win, itv);
            scan::apply_scan_params();
        }
    }
    if (doc.containsKey("ftmask")) {
        uint8_t m = doc["ftmask"];
        if (m != config::get().ft_mask) config::set_ftmask(m);
    }

    // Echo what was actually stored -- the values may have been clamped.
    char out[96];
    snprintf(out, sizeof(out),
             "{\"ok\":true,\"scan_win\":%u,\"scan_int\":%u,\"ftmask\":%u}",
             (unsigned)config::get().scan_window_ms,
             (unsigned)config::get().scan_interval_ms,
             (unsigned)config::get().ft_mask);
    req->send(200, "application/json", out);
}

void handle_post_ap(AsyncWebServerRequest* req) {
    const char* body = body_or_fail(req);
    if (!body) return;

    StaticJsonDocument<256> doc;
    if (deserializeJson(doc, body)) {
        req->send(400, "application/json", "{\"error\":\"json\"}");
        return;
    }
    const char* ssid = doc["ssid"] | "";
    const char* pass = doc["pass"] | "";
    // Reject rather than silently keeping the old credentials: the dashboard
    // reboots the device on a 200, so a silent no-op looked like a successful
    // change that had in fact never been applied.
    const size_t sl = strlen(ssid), pl = strlen(pass);
    if (sl == 0 || sl > 32) {
        req->send(400, "application/json", "{\"error\":\"ssid must be 1-32 chars\"}");
        return;
    }
    if (pl < 8 || pl > 63) {
        req->send(400, "application/json", "{\"error\":\"password must be 8-63 chars\"}");
        return;
    }
    config::set_ap(ssid, pass);
    req->send(200, "application/json", "{\"ok\":true}");
}

void handle_reboot(AsyncWebServerRequest* req) {
    req->send(200, "application/json", "{\"ok\":true}");
    schedule_restart(400);
}

void handle_reset(AsyncWebServerRequest* req) {
    config::reset_defaults();
    req->send(200, "application/json", "{\"ok\":true}");
    schedule_restart(400);
}

void handle_clear(AsyncWebServerRequest* req) {
    scan::clear_ring();
    req->send(200, "application/json", "{\"ok\":true}");
}

// -- Session state machine endpoints -----------------------------------------
// Legal transitions:
//   IDLE|PAUSED|STOPPED -> RECORDING   (via /api/session/record; clears ring)
//   RECORDING           -> PAUSED      (via /api/session/pause)
//   PAUSED              -> RECORDING   (via /api/session/resume)
//   RECORDING|PAUSED    -> STOPPED     (via /api/session/stop)
// Illegal transitions return HTTP 409 with the current + attempted state.

const char* target_name_for(const char* which) {
    if (!strcmp(which, "record") || !strcmp(which, "resume")) return "recording";
    if (!strcmp(which, "pause"))  return "paused";
    if (!strcmp(which, "stop"))   return "stopped";
    return "?";
}

void reply_transition(AsyncWebServerRequest* req, bool ok, const char* which, const char* from) {
    if (ok) {
        char body[80];
        snprintf(body, sizeof(body), "{\"ok\":true,\"state\":\"%s\"}",
                 session_pcap::state_name());
        req->send(200, "application/json", body);
    } else {
        char body[160];
        snprintf(body, sizeof(body),
                 "{\"error\":\"invalid transition\",\"from\":\"%s\",\"to\":\"%s\"}",
                 from, target_name_for(which));
        req->send(409, "application/json", body);
    }
}

void handle_session_record(AsyncWebServerRequest* req) {
    const char* from = session_pcap::state_name();
    reply_transition(req, session_pcap::cmd_record(), "record", from);
}
void handle_session_pause(AsyncWebServerRequest* req) {
    const char* from = session_pcap::state_name();
    reply_transition(req, session_pcap::cmd_pause(),  "pause",  from);
}
void handle_session_resume(AsyncWebServerRequest* req) {
    const char* from = session_pcap::state_name();
    reply_transition(req, session_pcap::cmd_resume(), "resume", from);
}
void handle_session_stop(AsyncWebServerRequest* req) {
    const char* from = session_pcap::state_name();
    reply_transition(req, session_pcap::cmd_stop(),   "stop",   from);
}

void handle_session_pcap(AsyncWebServerRequest* req) {
    // Download only permitted from STOPPED. The chunk reader takes the session
    // mutex per 4KB copy and reads straight out of the live ring. There is no
    // snapshot buffer -- the STOPPED guarantee is what makes it safe. If the
    // state changes mid-download (Record wipes the ring) read_chunk() returns
    // 0 and the chunked response truncates cleanly.
    if (session_pcap::state() != session_pcap::State::STOPPED) {
        req->send(409, "application/json",
            "{\"error\":\"invalid transition\",\"detail\":\"download only allowed from stopped\"}");
        return;
    }
    if (session_pcap::size() <= session_pcap::GLOBAL_HDR_LEN) {
        req->send(204, "application/vnd.tcpdump.pcap", "");
        return;
    }

    session_pcap::download_begin();
    // Balance the counter on disconnect, not on the chunk callback returning 0:
    // a client that aborts mid-download never reaches that final call, so the
    // in-flight count only ever climbed. onDisconnect fires exactly once per
    // request, on both clean completion and abort.
    req->onDisconnect([]() { session_pcap::download_end(); });
    AsyncWebServerResponse* r = req->beginChunkedResponse(
        "application/vnd.tcpdump.pcap",
        [](uint8_t* buf, size_t maxLen, size_t index) -> size_t {
            constexpr size_t CHUNK = 4096;
            size_t want = maxLen < CHUNK ? maxLen : CHUNK;
            return session_pcap::read_chunk(index, buf, want);
        });
    if (!r) {
        // new AsyncChunkedResponse returned null (heap exhausted, and this
        // build has no exceptions). Dereferencing it panics the device --
        // answer 503 instead, and release the in-flight count we just took
        // since onDisconnect still fires for this request.
        req->send(503, "application/json", "{\"error\":\"out of memory\"}");
        return;
    }
    char filename[64];
    snprintf(filename, sizeof(filename), "attachment; filename=\"ouispy-blesniff-%lu.pcap\"",
             (unsigned long)(millis() / 1000));
    r->addHeader("Content-Disposition", filename);
    r->addHeader("Cache-Control", "no-store");
    req->send(r);
}

} // namespace

uint32_t connected_clients() { return ws.count(); }
uint32_t ws_dropped()        { return g_ws_dropped; }

bool init() {
    boot_ms = millis();

    server.on("/", HTTP_GET, [](AsyncWebServerRequest* req){
        AsyncWebServerResponse* r = req->beginResponse(200, "text/html", (const uint8_t*)INDEX_HTML, strlen_P(INDEX_HTML));
        r->addHeader("Cache-Control", "no-store");
        req->send(r);
    });
    server.on("/api/config", HTTP_GET, handle_get_config);
    server.on("/api/config", HTTP_POST, handle_post_config, nullptr, accumulate_body);
    server.on("/api/ap",     HTTP_POST, handle_post_ap,     nullptr, accumulate_body);
    server.on("/api/reboot", HTTP_POST, handle_reboot);
    server.on("/api/reset", HTTP_POST, handle_reset);
    server.on("/api/clear", HTTP_POST, handle_clear);
    server.on("/api/session.pcap", HTTP_GET, handle_session_pcap);
    server.on("/api/session/record", HTTP_POST, handle_session_record);
    server.on("/api/session/pause",  HTTP_POST, handle_session_pause);
    server.on("/api/session/resume", HTTP_POST, handle_session_resume);
    server.on("/api/session/stop",   HTTP_POST, handle_session_stop);

    server.onNotFound([](AsyncWebServerRequest* req){ req->send(404, "text/plain", "not found"); });

    server.addHandler(&ws);
    server.begin();

    xTaskCreatePinnedToCore(&dashboard_task, "dash", 10240, nullptr, 3, &dash_task_h, 1);
    return true;
}

void tick() {
    ws.cleanupClients();
    const uint32_t at = g_restart_at;
    if (at && (int32_t)(millis() - at) >= 0) {
        Serial.flush();
        ESP.restart();
    }
}

} // namespace web_dashboard
