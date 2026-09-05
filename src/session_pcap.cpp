#include "session_pcap.h"
#include "nordic_pcap.h"

#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

namespace session_pcap {

namespace {

struct __attribute__((packed)) PcapGlobal {
    uint32_t magic;
    uint16_t vmaj, vmin;
    int32_t  tz;
    uint32_t sig;
    uint32_t snaplen;
    uint32_t linktype;
};

struct __attribute__((packed)) PcapRec {
    uint32_t ts_sec, ts_usec;
    uint32_t incl_len, orig_len;
};

// Tiered PSRAM allocation. First entry that succeeds wins; nothing falls
// through to DRAM (that path OOM-crashed the ESP32 previously).
#ifdef OUISPY_SESSION_CAP
// Test knob: a single small tier so the ring wraps in seconds instead of the
// ~40 minutes 6 MB takes at typical advert rates. tools/hwtest/wrap_test.py
// builds with PLATFORMIO_BUILD_FLAGS=-DOUISPY_SESSION_CAP=65536.
constexpr size_t CAP_TIERS[] = { OUISPY_SESSION_CAP };
#else
constexpr size_t CAP_TIERS[] = { 6 * 1024 * 1024, 4 * 1024 * 1024, 2 * 1024 * 1024 };
#endif

uint8_t*             g_buf     = nullptr;   // [0,GLOBAL_HDR_LEN) header, then the data ring
size_t               g_cap     = 0;         // whole allocation
size_t               g_dcap    = 0;         // data ring capacity = g_cap - GLOBAL_HDR_LEN
size_t               g_head    = 0;         // physical offset (in the data ring) of the oldest record
size_t               g_data    = 0;         // bytes of records currently held
uint32_t             g_dropped = 0;
SemaphoreHandle_t    g_lock    = nullptr;

volatile State       g_state          = State::IDLE;
volatile uint32_t    g_downloads      = 0;

// The data region is a circular buffer of PCAP records. Logical position L
// (0 = oldest byte) lives at physical g_head + L, wrapping at g_dcap. Records
// may straddle the wrap; the two helpers below split the copy. This replaced
// a linear buffer that reclaimed space by memmove()ing up to 3 MB of PSRAM
// under the lock -- a 100 ms+ stall of the writer every time the ring filled.
inline uint8_t* dring() { return g_buf + GLOBAL_HDR_LEN; }

void ring_write_locked(size_t logical, const void* src, size_t n) {
    size_t p = g_head + logical;
    if (p >= g_dcap) p -= g_dcap;
    const size_t first = (n < g_dcap - p) ? n : g_dcap - p;
    memcpy(dring() + p, src, first);
    if (n > first) memcpy(dring(), (const uint8_t*)src + first, n - first);
}

void ring_read_locked(size_t logical, void* dst, size_t n) {
    size_t p = g_head + logical;
    if (p >= g_dcap) p -= g_dcap;
    const size_t first = (n < g_dcap - p) ? n : g_dcap - p;
    memcpy(dst, dring() + p, first);
    if (n > first) memcpy((uint8_t*)dst + first, dring(), n - first);
}

void write_global_header_locked() {
    PcapGlobal g{};
    g.magic    = nordic_pcap::PCAP_MAGIC;
    g.vmaj     = nordic_pcap::PCAP_VER_MAJOR;
    g.vmin     = nordic_pcap::PCAP_VER_MINOR;
    g.snaplen  = nordic_pcap::PCAP_SNAPLEN;
    g.linktype = nordic_pcap::PCAP_LINKTYPE;
    memcpy(g_buf, &g, sizeof(g));
}

void reset_ring_locked() {
    write_global_header_locked();
    g_head    = 0;
    g_data    = 0;
    g_dropped = 0;
}

// Drop oldest records until `need` bytes are free. Lazy: one or two records
// per append once the ring is full, O(1) amortized, never a bulk move.
void reclaim_locked(size_t need) {
    while (g_dcap - g_data < need) {
        if (g_data < sizeof(PcapRec)) { reset_ring_locked(); return; }   // torn; cannot happen, but do not spin
        PcapRec rec;
        ring_read_locked(0, &rec, sizeof(rec));
        const size_t rec_total = sizeof(rec) + rec.incl_len;
        if (rec_total > g_data)      { reset_ring_locked(); return; }
        g_head += rec_total;
        if (g_head >= g_dcap) g_head -= g_dcap;
        g_data -= rec_total;
        g_dropped++;
    }
}

} // namespace

bool init() {
    if (g_buf) return true;
    g_lock = xSemaphoreCreateMutex();
    if (!g_lock) return false;

    for (size_t i = 0; i < sizeof(CAP_TIERS) / sizeof(CAP_TIERS[0]); ++i) {
        uint8_t* p = (uint8_t*)heap_caps_malloc(CAP_TIERS[i],
                                                MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (p) {
            g_buf  = p;
            g_cap  = CAP_TIERS[i];
            g_dcap = g_cap - GLOBAL_HDR_LEN;
            Serial.printf("[session_pcap] tier %u ok: %u bytes in PSRAM\n",
                          (unsigned)i, (unsigned)g_cap);
            break;
        }
        Serial.printf("[session_pcap] tier %u FAILED (%u bytes)\n",
                      (unsigned)i, (unsigned)CAP_TIERS[i]);
    }

    if (!g_buf) {
        Serial.println("[session_pcap] disabled -- no PSRAM tier available");
        vSemaphoreDelete(g_lock);
        g_lock = nullptr;
        return false;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);
    reset_ring_locked();
    g_state = State::IDLE;
    xSemaphoreGive(g_lock);
    return true;
}

State       state()      { return g_state; }
const char* state_name() {
    switch (g_state) {
        case State::IDLE:      return "idle";
        case State::RECORDING: return "recording";
        case State::PAUSED:    return "paused";
        case State::STOPPED:   return "stopped";
    }
    return "?";
}

bool cmd_record() {
    if (!g_buf || !g_lock) return false;
    // Legal from IDLE, PAUSED, STOPPED (i.e. anything but already RECORDING).
    if (g_state == State::RECORDING) return false;
    xSemaphoreTake(g_lock, portMAX_DELAY);
    reset_ring_locked();
    g_state = State::RECORDING;
    xSemaphoreGive(g_lock);
    return true;
}

bool cmd_pause() {
    if (!g_buf || !g_lock) return false;
    if (g_state != State::RECORDING) return false;
    g_state = State::PAUSED;
    return true;
}

bool cmd_resume() {
    if (!g_buf || !g_lock) return false;
    if (g_state != State::PAUSED) return false;
    g_state = State::RECORDING;
    return true;
}

bool cmd_stop() {
    if (!g_buf || !g_lock) return false;
    if (g_state != State::RECORDING && g_state != State::PAUSED) return false;
    g_state = State::STOPPED;
    return true;
}

void append(const scan::Frame& f) {
    if (!g_buf || !g_lock) return;
    if (g_state != State::RECORDING) return;

    // Serialize into a local stage buffer, then move it under the lock.
    static uint8_t stage[nordic_pcap::FRAME_OVERHEAD + scan::MAX_PAYLOAD];
    const size_t body    = nordic_pcap::build_frame(f, stage);
    const size_t rec_len = sizeof(PcapRec) + body;
    if (rec_len > g_dcap) return;

    PcapRec rec{};
    rec.ts_sec   = f.ts_sec;
    rec.ts_usec  = f.ts_usec;
    rec.incl_len = (uint32_t)body;
    rec.orig_len = (uint32_t)body;

    xSemaphoreTake(g_lock, portMAX_DELAY);

    // Re-check state after taking the lock -- a stop() could have raced in.
    if (g_state != State::RECORDING) {
        xSemaphoreGive(g_lock);
        return;
    }

    reclaim_locked(rec_len);
    ring_write_locked(g_data,               &rec,  sizeof(rec));
    ring_write_locked(g_data + sizeof(rec), stage, body);
    g_data += rec_len;

    xSemaphoreGive(g_lock);
}

size_t   size()      { return GLOBAL_HDR_LEN + g_data; }
size_t   capacity()  { return g_cap; }
uint32_t dropped()   { return g_dropped; }

size_t read_chunk(size_t offset, uint8_t* out, size_t len) {
    if (!g_buf || !g_lock) return 0;
    // Downloads are only served in STOPPED. If the state has moved on (Record
    // wiped the ring) we return 0 and the chunked response terminates cleanly.
    if (g_state != State::STOPPED) return 0;
    xSemaphoreTake(g_lock, portMAX_DELAY);
    size_t copied = 0;
    if (g_state == State::STOPPED) {
        // Logical file = fixed 24-byte header, then the ring oldest-first.
        if (offset < GLOBAL_HDR_LEN) {
            const size_t n = (len < GLOBAL_HDR_LEN - offset) ? len : GLOBAL_HDR_LEN - offset;
            memcpy(out, g_buf + offset, n);
            copied += n; offset += n; out += n; len -= n;
        }
        if (len && offset >= GLOBAL_HDR_LEN) {
            const size_t logical = offset - GLOBAL_HDR_LEN;
            if (logical < g_data) {
                const size_t n = (len < g_data - logical) ? len : g_data - logical;
                ring_read_locked(logical, out, n);
                copied += n;
            }
        }
    }
    xSemaphoreGive(g_lock);
    return copied;
}

void download_begin() { g_downloads++; }
void download_end()   { if (g_downloads) g_downloads--; }
uint32_t downloads_in_flight() { return g_downloads; }

} // namespace session_pcap
