#pragma once

#include <Arduino.h>
#include "scan.h"

// Builds LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR (256) payloads for both the
// USB PCAP stream and the in-memory session PCAP buffer.
namespace nordic_pcap {

// Sizes:
//  10-byte LE-LL-WITH-PHDR pseudo-header
// + 4-byte access address
// + 2-byte LL header (PDU type / flags / length)
// + 6-byte advertising address
// + 6-byte target address (ADV_DIRECT_IND only, synthesized zero -- see build_frame())
// + N-byte AdvData
// + 3-byte CRC (synthesized zero)
constexpr size_t PHDR_LEN         = 10;
constexpr size_t ACCESS_ADDR_LEN  = 4;
constexpr size_t LL_HDR_LEN       = 2;
constexpr size_t ADV_ADDR_LEN     = 6;
constexpr size_t TARGET_ADDR_LEN  = 6;
constexpr size_t CRC_LEN          = 3;

// Fixed overhead around the AdvData payload. Sized for the worst case
// (ADV_DIRECT_IND, which carries TargetA); other PDU types use less.
constexpr size_t FRAME_OVERHEAD =
    PHDR_LEN + ACCESS_ADDR_LEN + LL_HDR_LEN + ADV_ADDR_LEN + TARGET_ADDR_LEN + CRC_LEN;

// The advertising PDU header length field is 6 bits and covers AdvA (6 bytes)
// plus AdvData, so AdvData tops out here. build_frame() truncates to it.
constexpr uint16_t MAX_ADV_DATA = 0x3F - ADV_ADDR_LEN;   // 57

constexpr uint32_t PCAP_MAGIC        = 0xA1B2C3D4;
constexpr uint16_t PCAP_VER_MAJOR    = 2;
constexpr uint16_t PCAP_VER_MINOR    = 4;
constexpr uint32_t PCAP_LINKTYPE     = 256;  // LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR
constexpr uint32_t PCAP_SNAPLEN      = 512;

// Advertising channel access address (little-endian on wire: D6 BE 89 8E).
constexpr uint32_t ADV_ACCESS_ADDR   = 0x8E89BED6;

// Pseudo-header flags for advertising packets. Bit layout per Wireshark's
// btle_rf dissector (verified against tshark -G fields):
//   bit 0 (0x0001) dewhitened
//   bit 1 (0x0002) signal-power-valid
//   bit 4 (0x0010) reference-access-address-valid
//   bits 7-9 (0x0380) PDU Type: 0=Advertising, 4=CIS C->P, etc.
//   bit 10 (0x0400) CRC checked
//   bit 11 (0x0800) CRC valid
// We set the three "valid" markers and leave PDU Type = 0 (Advertising).
// CRC bits are cleared because we synthesize zero CRC bytes -- claiming
// "checked" would make Wireshark flag every frame as CRC-bad.
constexpr uint16_t PHDR_FLAGS        = 0x0013;
constexpr uint16_t PHDR_FLAG_SIGNAL_POWER_VALID = 0x0002;

// Serialize one scan::Frame into a LE_LL_WITH_PHDR buffer.
// `out` must have room for FRAME_OVERHEAD + f.payload_len bytes.
// Returns bytes written.
size_t build_frame(const scan::Frame& f, uint8_t* out);

// Convenience: the total serialized size for a Frame (post-truncation).
inline size_t frame_size(const scan::Frame& f) {
    return FRAME_OVERHEAD +
           (f.payload_len > MAX_ADV_DATA ? MAX_ADV_DATA : f.payload_len);
}

} // namespace nordic_pcap
