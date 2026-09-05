#include "nordic_pcap.h"
#include <string.h>

namespace nordic_pcap {

size_t build_frame(const scan::Frame& f, uint8_t* out) {
    uint8_t* p = out;

    // ADV_DIRECT_IND's body is spec-fixed at AdvA+TargetA with no AdvData at
    // all (BT Core Spec Vol 6 Part B §2.3.1.2); NimBLE's advertising-report
    // callback never surfaces an AdvData length for it, but guard anyway so a
    // future library change can't combine a real TargetA with AdvData and
    // overflow the 6-bit length field below.
    const bool is_direct = (f.ll_pdu_type == scan::LL_ADV_DIRECT_IND);

    // The legacy advertising PDU length field covers AdvA + AdvData and is 6
    // bits wide, so the payload cannot exceed MAX_ADV_DATA. Masking an
    // over-long length (as this used to) wraps it to a small bogus value and
    // Wireshark then mis-dissects the record. Truncate instead -- a short
    // packet with a correct length beats a full one with a lying header.
    uint16_t payload_len = is_direct ? 0 : f.payload_len;
    if (payload_len > MAX_ADV_DATA) payload_len = MAX_ADV_DATA;

    // -------- 10-byte LE-LL-WITH-PHDR pseudo-header --------
    // Byte 0: RF channel index (0..39). 0xFF means unknown; Wireshark tolerates
    // any value in the 0..39 range, so map unknown to 39 (a valid adv channel).
    uint8_t ch = (f.channel <= 39) ? f.channel : 39;
    *p++ = ch;
    *p++ = (uint8_t)f.rssi;   // signal power (int8 dBm)
    *p++ = 0;                 // noise power (unused; flag bit not set anyway)
    *p++ = 0;                 // access-address offenses
    // Bytes 4..7: reference access address (u32 LE) — advertising AA
    *p++ = (uint8_t)(ADV_ACCESS_ADDR      );
    *p++ = (uint8_t)(ADV_ACCESS_ADDR >>  8);
    *p++ = (uint8_t)(ADV_ACCESS_ADDR >> 16);
    *p++ = (uint8_t)(ADV_ACCESS_ADDR >> 24);
    // Bytes 8..9: flags (u16 LE). RSSI 127 (0x7F) is the HCI "not available"
    // sentinel (BT Core Spec Vol 4 Part E §7.7.65.2) -- clear the
    // signal-power-valid bit for it instead of asserting a fabricated -1 dBm
    // reading as authoritative.
    uint16_t flags = PHDR_FLAGS;
    if (f.rssi == 127) flags &= ~PHDR_FLAG_SIGNAL_POWER_VALID;
    *p++ = (uint8_t)(flags      );
    *p++ = (uint8_t)(flags >>  8);

    // -------- 4-byte access address (on-air, little-endian) --------
    *p++ = (uint8_t)(ADV_ACCESS_ADDR      );
    *p++ = (uint8_t)(ADV_ACCESS_ADDR >>  8);
    *p++ = (uint8_t)(ADV_ACCESS_ADDR >> 16);
    *p++ = (uint8_t)(ADV_ACCESS_ADDR >> 24);

    // -------- 2-byte LL header --------
    // Byte 0: [ChSel(1) | TxAdd(1) | RxAdd(1) | RFU(1) | PDU type(4)]
    //         bit 0-3 = PDU type
    //         bit 6   = TxAdd (1 if AdvA is random)
    //         bit 7   = RxAdd (1 if TargetA is random -- ADV_DIRECT_IND only)
    // RxAdd is left clear: the HCI advertising report does not carry TargetA's
    // address type (that arrives in a separate directed-report event NimBLE
    // does not surface), so asserting it was a guess written into the capture.
    uint8_t hdr0 = f.ll_pdu_type & 0x0F;
    bool tx_random = (f.addr_type != scan::ADDR_PUBLIC && f.addr_type != scan::ADDR_UNKNOWN);
    if (tx_random) hdr0 |= 0x40;
    // Byte 1: length in low 6 bits (AdvA + TargetA [ADV_DIRECT_IND only] + AdvData)
    const size_t target_a_len = is_direct ? TARGET_ADDR_LEN : 0;
    uint8_t len_field = (uint8_t)((ADV_ADDR_LEN + target_a_len + payload_len) & 0x3F);
    *p++ = hdr0;
    *p++ = len_field;

    // -------- 6-byte advertising address (little-endian on wire) --------
    // scan::Frame.addr is stored MSB-last in our conventional order (addr[5] = MSB),
    // matching how BLE spec describes address bytes. On the wire the address is
    // little-endian, so byte 0 of the AA is our addr[0]. Same convention already
    // used in ouispy-pcap for MAC serialization — write bytes in stored order.
    for (int i = 0; i < 6; ++i) *p++ = f.addr[i];

    // -------- 6-byte target address (ADV_DIRECT_IND only) --------
    // NimBLE's advertising-report callback never surfaces TargetA, so it is
    // synthesized as zero -- the same tradeoff already made for the CRC below.
    // A zeroed-but-present TargetA keeps this PDU's body at its spec-fixed 12
    // bytes; omitting it (the previous behaviour) undersized the Length field
    // and desynced a spec-compliant dissector's AdvData/CRC framing for every
    // ADV_DIRECT_IND frame.
    if (is_direct) {
        memset(p, 0, TARGET_ADDR_LEN);
        p += TARGET_ADDR_LEN;
    }

    // -------- AdvData --------
    if (payload_len) {
        memcpy(p, f.payload, payload_len);
        p += payload_len;
    }

    // -------- 3-byte CRC (synthesized zero — we don't have the real one) --------
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;

    return (size_t)(p - out);
}

} // namespace nordic_pcap
