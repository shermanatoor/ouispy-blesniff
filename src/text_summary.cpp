#include "text_summary.h"

#include <string.h>
#include <stdio.h>
#include <ctype.h>

namespace text_summary {

// AD types (Assigned Numbers / Generic Access Profile)
namespace ad {
constexpr uint8_t FLAGS                    = 0x01;
constexpr uint8_t INCOMPLETE_16BIT_UUIDS   = 0x02;
constexpr uint8_t COMPLETE_16BIT_UUIDS     = 0x03;
constexpr uint8_t INCOMPLETE_32BIT_UUIDS   = 0x04;
constexpr uint8_t COMPLETE_32BIT_UUIDS     = 0x05;
constexpr uint8_t INCOMPLETE_128BIT_UUIDS  = 0x06;
constexpr uint8_t COMPLETE_128BIT_UUIDS    = 0x07;
constexpr uint8_t SHORTENED_LOCAL_NAME     = 0x08;
constexpr uint8_t COMPLETE_LOCAL_NAME      = 0x09;
constexpr uint8_t TX_POWER_LEVEL           = 0x0A;
constexpr uint8_t SERVICE_DATA_16          = 0x16;
constexpr uint8_t SERVICE_DATA_32          = 0x20;
constexpr uint8_t SERVICE_DATA_128         = 0x21;
constexpr uint8_t MANUFACTURER_SPECIFIC    = 0xFF;
} // namespace ad

const char* ll_type_name(uint8_t t) {
    switch (t) {
        case scan::LL_ADV_IND:         return "ADV_IND";
        case scan::LL_ADV_DIRECT_IND:  return "ADV_DIRECT";
        case scan::LL_ADV_NONCONN_IND: return "ADV_NONCONN";
        case scan::LL_SCAN_REQ:        return "SCAN_REQ";
        case scan::LL_SCAN_RSP:        return "SCAN_RSP";
        case scan::LL_CONNECT_IND:     return "CONNECT_REQ";
        case scan::LL_ADV_SCAN_IND:    return "ADV_SCAN";
        // scan::LL_UNKNOWN lands here, as does any value we never emit.
        default:                       return "ADV_?";
    }
}

const char* addr_type_short(uint8_t a) {
    switch (a) {
        case scan::ADDR_PUBLIC:        return "pub";
        case scan::ADDR_RANDOM_STATIC: return "rnd-s";
        case scan::ADDR_RANDOM_NRP:    return "rnd-nrp";
        case scan::ADDR_RANDOM_RPA:    return "rnd-rpa";
        default:                       return "unk";
    }
}

void format_addr(const uint8_t addr[6], char* out18) {
    // Address printed MSB-first (addr[5] is MSB, per BLE spec convention).
    snprintf(out18, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);
}

// AD-structure iterator: for each (type, len, data), invoke `visit(type, data, dlen)`.
// dlen is the AD data length (excludes the type byte).
template <typename V>
void for_each_ad(const scan::Frame& f, V visit) {
    size_t i = 0;
    while (i < f.payload_len) {
        uint8_t ad_len = f.payload[i];
        if (ad_len == 0) { i++; continue; }
        if (i + 1 + ad_len > f.payload_len) return;
        uint8_t ad_type = f.payload[i + 1];
        const uint8_t* d = f.payload + i + 2;
        uint8_t dlen = ad_len - 1;
        if (!visit(ad_type, d, dlen)) return;
        i += 1 + ad_len;
    }
}

void extract_name(const scan::Frame& f, char* out, size_t out_sz) {
    out[0] = 0;
    // Prefer the complete name. Taking whichever AD came first meant a device
    // advertising SHORTENED before COMPLETE showed the truncated name, which
    // also weakens the vendor name-substring match.
    bool have_complete = false;
    for_each_ad(f, [&](uint8_t type, const uint8_t* d, uint8_t dlen) -> bool {
        const bool complete = (type == ad::COMPLETE_LOCAL_NAME);
        if (!complete && type != ad::SHORTENED_LOCAL_NAME) return true;
        if (have_complete) return true;              // nothing can improve on it
        size_t n = dlen;
        if (n >= out_sz) n = out_sz - 1;
        for (size_t k = 0; k < n; ++k) {
            uint8_t c = d[k];
            out[k] = (c >= 0x20 && c < 0x7F) ? (char)c : '.';
        }
        out[n] = 0;
        have_complete = complete;
        return !complete;                            // keep looking only while shortened
    });
}

int32_t manufacturer_id(const scan::Frame& f) {
    int32_t id = -1;
    for_each_ad(f, [&](uint8_t type, const uint8_t* d, uint8_t dlen) -> bool {
        if (type == ad::MANUFACTURER_SPECIFIC && dlen >= 2) {
            id = (uint16_t)d[0] | ((uint16_t)d[1] << 8);
            return false;
        }
        return true;
    });
    return id;
}

// Bluetooth SIG company identifiers, checked by tools/validate_ids.py. Four
// consumer entries were mislabelled (0x00D2 is Renesas not Sonos, 0x008A
// Jawbone not Bose, 0x2C00 unassigned, 0x0002 Intel not Nokia) and are fixed.
// 0x0BF3 and 0x004D are field observations from colonelpanichacks/ouispy-detector's
// OUI database (registry says PONE Biometrics / Staccato); kept, with the
// registry CIDs for DJI and Parrot added alongside.
const char* mfr_shortname(uint16_t id) {
    switch (id) {
        // Big consumer
        case 0x004C: return "Apple";
        case 0x0006: return "Microsoft";
        case 0x00E0: return "Google";
        case 0x0075: return "Samsung";
        case 0x0171: return "Amazon";
        case 0x038F: return "Xiaomi";
        case 0x0087: return "Garmin";
        case 0x05A7: return "Sonos";
        case 0x009E: return "Bose";
        case 0x02F2: return "GoPro";
        // Silicon / dev
        case 0x0059: return "Nordic";
        case 0x0131: return "Cypress";
        case 0x02E5: return "Espressif";
        case 0x000F: return "Broadcom";
        case 0x0001: return "Nokia";
        case 0x0157: return "Anhui Huami";
        case 0x0499: return "Ruuvi";
        // Surveillance / drones / smartglasses
        case 0x034D: return "Axon/TASER";
        case 0x09C8: return "XUNTONG (Flock battery)";
        case 0x01AB: return "Meta";
        case 0x058E: return "Meta (Reality Labs)";
        case 0x0D53: return "Luxottica (Meta/Ray-Ban)";
        case 0x08AA: return "DJI";
        case 0x0BF3: return "DJI (observed)";
        case 0x0043: return "Parrot Automotive";
        case 0x004D: return "Parrot (observed)";
        default:     return "?";
    }
}

// Bluetooth Base UUID, little-endian as it appears on air, minus the 4-byte
// short value at offset 12: 0000xxxx-0000-1000-8000-00805F9B34FB.
static const uint8_t BT_BASE_LE[12] = {
    0xFB,0x34,0x9B,0x5F,0x80,0x00,0x00,0x80,0x00,0x10,0x00,0x00
};

// True when a 128-bit UUID (little-endian, 16 bytes) is a Bluetooth Base UUID
// carrying a 16-bit value, and writes that value to *out16.
static bool uuid128_to_16(const uint8_t* d, uint16_t* out16) {
    if (memcmp(d, BT_BASE_LE, sizeof(BT_BASE_LE)) != 0) return false;
    if (d[14] != 0 || d[15] != 0) return false;          // 32-bit value, not 16
    *out16 = (uint16_t)d[12] | ((uint16_t)d[13] << 8);
    return true;
}

// Collects the advertised service UUIDs as comma-joined 16-bit hex.
//
// Reads the 16-, 32- and 128-bit UUID lists and the three Service Data types.
// 32- and 128-bit UUIDs are reduced to their 16-bit form when they sit in the
// Bluetooth Base range, which is how vendors normally advertise an assigned
// short UUID; a genuinely custom 128-bit UUID has no short form and is skipped
// rather than blow this buffer (callers pass 80 bytes and feed the result into
// a 512-byte JSON document).
//
// Parsing only 0x02/0x03 was a real gap: the same UUID may be advertised as a
// 16-bit list entry, a 128-bit list entry, or a Service Data prefix, so vendor
// matching on e.g. the Raven 0x3100-0x3500 services or Meta 0xFEB8 silently
// missed every device that chose a different encoding.
size_t extract_service_uuids(const scan::Frame& f, char* out, size_t out_sz) {
    size_t   written = 0;
    bool     first   = true;
    uint16_t seen[16];
    uint8_t  seen_n  = 0;

    auto emit = [&](uint16_t u) {
        for (uint8_t i = 0; i < seen_n; ++i) if (seen[i] == u) return;  // same UUID, two encodings
        if (seen_n < (uint8_t)(sizeof(seen) / sizeof(seen[0]))) seen[seen_n++] = u;
        char buf[10];
        int n = snprintf(buf, sizeof(buf), first ? "0x%04X" : ",0x%04X", u);
        if (n > 0 && written + (size_t)n < out_sz) {
            memcpy(out + written, buf, n);
            written += n;
            first = false;
        }
    };

    for_each_ad(f, [&](uint8_t type, const uint8_t* d, uint8_t dlen) -> bool {
        switch (type) {
            case ad::INCOMPLETE_16BIT_UUIDS:
            case ad::COMPLETE_16BIT_UUIDS:
                for (size_t k = 0; k + 1 < dlen; k += 2)
                    emit((uint16_t)d[k] | ((uint16_t)d[k+1] << 8));
                break;
            case ad::INCOMPLETE_32BIT_UUIDS:
            case ad::COMPLETE_32BIT_UUIDS:
                for (size_t k = 0; k + 3 < dlen; k += 4)
                    if (d[k+2] == 0 && d[k+3] == 0)      // reducible to 16 bits
                        emit((uint16_t)d[k] | ((uint16_t)d[k+1] << 8));
                break;
            case ad::INCOMPLETE_128BIT_UUIDS:
            case ad::COMPLETE_128BIT_UUIDS: {
                uint16_t u;
                for (size_t k = 0; k + 15 < dlen; k += 16)
                    if (uuid128_to_16(d + k, &u)) emit(u);
                break;
            }
            // Service Data carries its UUID as the leading bytes of the value.
            case ad::SERVICE_DATA_16:
                if (dlen >= 2) emit((uint16_t)d[0] | ((uint16_t)d[1] << 8));
                break;
            case ad::SERVICE_DATA_32:
                if (dlen >= 4 && d[2] == 0 && d[3] == 0)
                    emit((uint16_t)d[0] | ((uint16_t)d[1] << 8));
                break;
            case ad::SERVICE_DATA_128: {
                uint16_t u;
                if (dlen >= 16 && uuid128_to_16(d, &u)) emit(u);
                break;
            }
            default: break;
        }
        return true;
    });
    if (written < out_sz) out[written] = 0;
    return written;
}

uint8_t traits(const scan::Frame& f) {
    uint8_t t = 0;
    if (f.tx_power != INT8_MIN) t |= TR_HAS_TXPOWER;
    if (f.ll_pdu_type == scan::LL_ADV_IND || f.ll_pdu_type == scan::LL_ADV_DIRECT_IND) {
        t |= TR_CONNECTABLE;
    }
    for_each_ad(f, [&](uint8_t type, const uint8_t*, uint8_t) -> bool {
        if (type == ad::COMPLETE_LOCAL_NAME || type == ad::SHORTENED_LOCAL_NAME) t |= TR_HAS_NAME;
        if (type == ad::MANUFACTURER_SPECIFIC)                                    t |= TR_HAS_MFR;
        if (type == ad::SERVICE_DATA_16 || type == ad::SERVICE_DATA_32 ||
            type == ad::SERVICE_DATA_128)                                         t |= TR_HAS_SVC_DATA;
        return true;
    });
    return t;
}

size_t format_line(const scan::Frame& f, char* out, size_t out_sz) {
    char addr[18]; format_addr(f.addr, addr);
    char name[32] = {0};
    extract_name(f, name, sizeof(name));
    char svc[80]; svc[0] = 0;
    extract_service_uuids(f, svc, sizeof(svc));
    int32_t mfr = manufacturer_id(f);

    // Channel: firmware doesn't get per-advert channel; print 0xFF as "?"
    char chbuf[4];
    if (f.channel <= 39) snprintf(chbuf, sizeof(chbuf), "%u", f.channel);
    else                 strlcpy(chbuf, "?", sizeof(chbuf));

    // snprintf returns the length it *would* have written, so every append has
    // to be clamped back to the buffer. The returned length is handed straight
    // to Serial.write(), and an unclamped offset would read past `out`.
    size_t off = 0;
    auto append = [&](int n) {
        if (n <= 0) return;
        off += (size_t)n;
        if (off >= out_sz) off = out_sz - 1;   // truncated; NUL already at out_sz-1
    };

    append(snprintf(out, out_sz, "[Ch%s RSSI%ddBm] %s %s:%s",
                    chbuf, (int)f.rssi,
                    ll_type_name(f.ll_pdu_type),
                    addr_type_short(f.addr_type),
                    addr));

    if (name[0] && off + 1 < out_sz) {
        append(snprintf(out + off, out_sz - off, " name=\"%s\"", name));
    }
    if (svc[0] && off + 1 < out_sz) {
        append(snprintf(out + off, out_sz - off, " svc=%s", svc));
    }
    if (mfr >= 0 && off + 1 < out_sz) {
        append(snprintf(out + off, out_sz - off, " mfr=%04X(%s)",
                        (unsigned)mfr, mfr_shortname((uint16_t)mfr)));
    }
    if (off + 1 < out_sz) {
        out[off++] = '\n';
        out[off] = 0;
    }
    return off;
}

} // namespace text_summary
