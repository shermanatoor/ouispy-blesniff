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

    printf("\n%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES PRESENT");
    return g_fail ? 1 : 0;
}
