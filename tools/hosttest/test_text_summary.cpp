// Host-side unit test for text_summary.cpp's AD-structure parsing. No Arduino
// framework needed: it only touches for_each_ad/extract_name/
// extract_service_uuids, which are pure buffer parsing over scan::Frame.
//
// Build & run:
//   g++ -std=c++17 -I src -o test_text_summary tools/hosttest/test_text_summary.cpp && ./test_text_summary
#include <cassert>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>

// ---- minimal Arduino stand-in; real scan::Frame comes from src/scan.h ----
using String = int; // unused by the functions under test
#define F(x) x

#include "../../src/scan.h"

#include "../../src/text_summary.cpp"

// ---- test helpers -----------------------------------------------------------
static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL  %s :: %s:%d\n", msg, __FILE__, __LINE__); g_fail++; } \
    else printf("PASS  %s\n", msg); \
} while (0)

static scan::Frame mkframe() {
    scan::Frame f{};
    f.channel = 0xFF; f.tx_power = INT8_MIN;
    return f;
}

static void push_ad(scan::Frame& f, uint8_t type, const uint8_t* data, uint8_t dlen) {
    uint8_t* p = f.payload + f.payload_len;
    p[0] = dlen + 1; p[1] = type;
    if (dlen) memcpy(p + 2, data, dlen);
    f.payload_len += 2 + dlen;
}

static void le16(uint8_t* out, uint16_t v) { out[0] = v & 0xFF; out[1] = v >> 8; }

// 128-bit Bluetooth Base UUID carrying `short_val`, little-endian on air.
static void base128_le(uint8_t* out, uint16_t short_val) {
    static const uint8_t BASE[16] = {
        0xFB,0x34,0x9B,0x5F,0x80,0x00,0x00,0x80,0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00};
    memcpy(out, BASE, 16);
    out[12] = short_val & 0xFF; out[13] = short_val >> 8;
}

int main() {
    // ---- 16-bit UUID list (baseline, pre-existing behaviour) ----
    {
        auto f = mkframe();
        uint8_t d[4]; le16(d, 0xFEB8); le16(d + 2, 0x180A);
        push_ad(f, 0x03, d, sizeof(d));
        char out[80] = {0};
        size_t n = text_summary::extract_service_uuids(f, out, sizeof(out));
        CHECK(n > 0 && std::string(out) == "0xFEB8,0x180A", "16-bit UUID list parses");
    }

    // ---- 128-bit Base UUID reduces to its 16-bit form ----
    {
        auto f = mkframe();
        uint8_t d[16]; base128_le(d, 0x3100);
        push_ad(f, 0x07, d, sizeof(d));   // COMPLETE_128BIT_UUIDS
        char out[80] = {0};
        size_t n = text_summary::extract_service_uuids(f, out, sizeof(out));
        CHECK(n > 0 && std::string(out) == "0x3100", "128-bit Base UUID reduces to 0x3100 (Raven)");
    }

    // ---- a genuinely custom 128-bit UUID does NOT reduce, does NOT crash ----
    {
        auto f = mkframe();
        // Nordic UART service: 6E400001-B5A3-F393-E0A9-E50E24DCCA9E, on-air LE.
        uint8_t d[16] = {0x9E,0xCA,0xDC,0x24,0x0E,0xE5,0xA9,0xE0,
                         0x93,0xF3,0xA3,0xB5,0x01,0x00,0x40,0x6E};
        push_ad(f, 0x07, d, sizeof(d));
        char out[80] = {0};
        size_t n = text_summary::extract_service_uuids(f, out, sizeof(out));
        CHECK(n == 0 && out[0] == 0, "custom 128-bit UUID does not falsely reduce");
    }

    // ---- 32-bit UUID reduces when high 16 bits are zero ----
    {
        auto f = mkframe();
        uint8_t d[4] = {0x8F, 0xFE, 0x00, 0x00};   // 0x0000FE8F LE
        push_ad(f, 0x05, d, sizeof(d));            // COMPLETE_32BIT_UUIDS
        char out[80] = {0};
        size_t n = text_summary::extract_service_uuids(f, out, sizeof(out));
        CHECK(n > 0 && std::string(out) == "0xFE8F", "32-bit UUID reduces to 16-bit");
    }

    // ---- Service Data (16-bit prefix) is read ----
    {
        auto f = mkframe();
        uint8_t d[3]; le16(d, 0xFD5F); d[2] = 0x01; // one payload byte after the UUID
        push_ad(f, 0x16, d, sizeof(d));             // SERVICE_DATA_16
        char out[80] = {0};
        size_t n = text_summary::extract_service_uuids(f, out, sizeof(out));
        CHECK(n > 0 && std::string(out) == "0xFD5F", "Service Data 16-bit UUID read");
    }

    // ---- Service Data (128-bit prefix), Raven's real encoding shape ----
    {
        auto f = mkframe();
        uint8_t d[17]; base128_le(d, 0x3200); d[16] = 0xAA;
        push_ad(f, 0x21, d, sizeof(d));             // SERVICE_DATA_128
        char out[80] = {0};
        size_t n = text_summary::extract_service_uuids(f, out, sizeof(out));
        CHECK(n > 0 && std::string(out) == "0x3200", "Service Data 128-bit UUID reduces (Raven shape)");
    }

    // ---- duplicate suppression: same UUID via list AND service data ----
    {
        auto f = mkframe();
        uint8_t d16[2]; le16(d16, 0xFEB8);
        push_ad(f, 0x03, d16, sizeof(d16));
        uint8_t dsd[3]; le16(dsd, 0xFEB8); dsd[2] = 0x00;
        push_ad(f, 0x16, dsd, sizeof(dsd));
        char out[80] = {0};
        size_t n = text_summary::extract_service_uuids(f, out, sizeof(out));
        CHECK(n > 0 && std::string(out) == "0xFEB8", "duplicate UUID across encodings suppressed");
    }

    // ---- multiple distinct UUIDs across different AD types in one frame ----
    {
        auto f = mkframe();
        uint8_t d16[2]; le16(d16, 0xFC81);
        push_ad(f, 0x03, d16, sizeof(d16));
        uint8_t d128[16]; base128_le(d128, 0x3100);
        push_ad(f, 0x07, d128, sizeof(d128));
        char out[80] = {0};
        size_t n = text_summary::extract_service_uuids(f, out, sizeof(out));
        CHECK(n > 0 && std::string(out) == "0xFC81,0x3100", "mixed 16-bit + 128-bit UUIDs in one frame");
    }

    // ---- name: COMPLETE arriving after SHORTENED wins ----
    {
        auto f = mkframe();
        push_ad(f, 0x08, (const uint8_t*)"Short", 5);      // SHORTENED_LOCAL_NAME
        push_ad(f, 0x09, (const uint8_t*)"CompleteName", 12); // COMPLETE_LOCAL_NAME
        char name[32] = {0};
        text_summary::extract_name(f, name, sizeof(name));
        CHECK(std::string(name) == "CompleteName", "complete name wins even when shortened comes first");
    }

    // ---- name: only SHORTENED present -> still returned ----
    {
        auto f = mkframe();
        push_ad(f, 0x08, (const uint8_t*)"OnlyShort", 9);
        char name[32] = {0};
        text_summary::extract_name(f, name, sizeof(name));
        CHECK(std::string(name) == "OnlyShort", "shortened name used when no complete name present");
    }

    // ---- name: COMPLETE before SHORTENED (order should not matter) ----
    {
        auto f = mkframe();
        push_ad(f, 0x09, (const uint8_t*)"CompleteFirst", 13);
        push_ad(f, 0x08, (const uint8_t*)"Shrt", 4);
        char name[32] = {0};
        text_summary::extract_name(f, name, sizeof(name));
        CHECK(std::string(name) == "CompleteFirst", "complete name kept regardless of AD order");
    }

    // ================= adversarial: malformed AD structures =================
    // A BLE advertisement is attacker-controlled data from the air -- anyone
    // in range can craft a payload. These push scan::Frame.payload directly
    // (bypassing push_ad's well-formed encoder) to exercise for_each_ad()'s
    // own bounds checks, then extract_* on top of it. Built to run under
    // -fsanitize=address,undefined; a real OOB read here is a crash any
    // nearby device could trigger, not just a logic mismatch.

    // AD length byte claims more data than the payload actually holds.
    {
        auto f = mkframe();
        f.payload[0] = 0xFF;              // "254 bytes of AD data follow"
        f.payload[1] = 0x03;              // COMPLETE_16BIT_UUIDS
        f.payload[2] = 0xAA;              // only 1 byte of real data present
        f.payload_len = 3;
        char out[80] = {0};
        size_t n = text_summary::extract_service_uuids(f, out, sizeof(out));
        CHECK(n == 0 && out[0] == 0, "AD claiming overrun length yields nothing, no OOB read");

        char name[32] = {0};
        text_summary::extract_name(f, name, sizeof(name));
        CHECK(name[0] == 0, "extract_name on the same overrun frame: no crash, no output");
    }

    // 128-bit UUID AD whose declared length is not a multiple of 16 (a
    // trailing partial UUID) -- the incomplete tail must be ignored, not read.
    {
        auto f = mkframe();
        uint8_t d[16 + 5];                // one full UUID + 5 leftover bytes
        base128_le(d, 0xFEB8);
        memset(d + 16, 0x41, 5);
        push_ad(f, 0x07, d, sizeof(d));
        char out[80] = {0};
        size_t n = text_summary::extract_service_uuids(f, out, sizeof(out));
        CHECK(n > 0 && std::string(out) == "0xFEB8",
              "128-bit UUID list with a non-multiple-of-16 trailing remainder: only the full UUID read");
    }

    // 32-bit UUID AD whose declared length is not a multiple of 4.
    {
        auto f = mkframe();
        uint8_t d[4 + 3] = {0x8F, 0xFE, 0x00, 0x00, 0x11, 0x22, 0x33};
        push_ad(f, 0x05, d, sizeof(d));
        char out[80] = {0};
        size_t n = text_summary::extract_service_uuids(f, out, sizeof(out));
        CHECK(n > 0 && std::string(out) == "0xFE8F",
              "32-bit UUID list with a non-multiple-of-4 trailing remainder: only the full UUID read");
    }

    // Service Data ADs one byte short of the minimum this code reads from.
    {
        auto f = mkframe();
        uint8_t one = 0xAA;
        push_ad(f, 0x16, &one, 1);         // SERVICE_DATA_16 needs 2 bytes, has 1
        char out[80] = {0};
        size_t n = text_summary::extract_service_uuids(f, out, sizeof(out));
        CHECK(n == 0, "1-byte SERVICE_DATA_16 (needs 2): skipped, no OOB read");
    }
    {
        auto f = mkframe();
        uint8_t three[3] = {0x11, 0x22, 0x33};
        push_ad(f, 0x20, three, 3);         // SERVICE_DATA_32 needs 4 bytes, has 3
        char out[80] = {0};
        size_t n = text_summary::extract_service_uuids(f, out, sizeof(out));
        CHECK(n == 0, "3-byte SERVICE_DATA_32 (needs 4): skipped, no OOB read");
    }
    {
        auto f = mkframe();
        uint8_t fifteen[15]; memset(fifteen, 0x55, sizeof(fifteen));
        push_ad(f, 0x21, fifteen, sizeof(fifteen));   // SERVICE_DATA_128 needs 16, has 15
        char out[80] = {0};
        size_t n = text_summary::extract_service_uuids(f, out, sizeof(out));
        CHECK(n == 0, "15-byte SERVICE_DATA_128 (needs 16): skipped, no OOB read");
    }

    // Zero-length AD entries (legal padding some stacks emit) interleaved
    // with real ones must not desync the parser.
    {
        auto f = mkframe();
        f.payload[0] = 0x00;               // zero-length AD (skip one byte)
        uint8_t d[2]; le16(d, 0xFC81);
        // manually place a well-formed 16-bit UUID AD right after the zero pad
        f.payload[1] = 0x03; f.payload[2] = 0x03; f.payload[3] = d[0]; f.payload[4] = d[1];
        f.payload_len = 5;
        char out[80] = {0};
        size_t n = text_summary::extract_service_uuids(f, out, sizeof(out));
        CHECK(n > 0 && std::string(out) == "0xFC81",
              "zero-length AD padding before a real AD does not desync the parser");
    }

    // Maximum-size payload (256 bytes, scan::MAX_PAYLOAD) packed with the
    // smallest possible AD structures (length=1, i.e. a bare type byte with
    // no data) back to back -- worst case for for_each_ad()'s loop bound.
    {
        auto f = mkframe();
        f.ll_pdu_type = scan::LL_ADV_NONCONN_IND;   // keep traits() to just what this test checks
        for (size_t i = 0; i + 1 < scan::MAX_PAYLOAD; i += 2) {
            f.payload[i] = 1;              // length=1: just the type byte, no data
            f.payload[i + 1] = 0xFF;        // MANUFACTURER_SPECIFIC, but dlen=0
        }
        f.payload_len = scan::MAX_PAYLOAD;
        char out[80] = {0};
        size_t n = text_summary::extract_service_uuids(f, out, sizeof(out));
        CHECK(n == 0, "max-size payload of empty-data ADs: parses to completion, no crash");
        char name[32] = {0};
        text_summary::extract_name(f, name, sizeof(name));
        CHECK(name[0] == 0, "same max-size payload through extract_name: no crash");
        uint8_t tr = text_summary::traits(f);
        CHECK(tr == text_summary::TR_HAS_MFR, "same payload through traits(): MFR bit set, no crash");
    }

    // AD length byte claiming more data than actually remains in the payload,
    // positioned so i+1+ad_len computes right at the size_t/uint8_t boundary
    // -- must reject (return early), not read past payload_len or wrap.
    {
        auto f = mkframe();
        f.payload[0] = 0xFF;   // ad_len=255 -> claims 254 bytes of data after the type byte
        f.payload[1] = 0x03;
        f.payload_len = 200;   // 0+1+255=256 > 200: genuinely overruns this payload
        char out[80] = {0};
        size_t n = text_summary::extract_service_uuids(f, out, sizeof(out));
        CHECK(n == 0, "AD length claiming more than remains in the payload: rejected, no OOB read");
    }

    printf("\n%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES PRESENT");
    return g_fail ? 1 : 0;
}
