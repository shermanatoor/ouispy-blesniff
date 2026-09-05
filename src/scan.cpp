#include "scan.h"
#include "config.h"

#include <NimBLEDevice.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <sys/time.h>

#include <atomic>

namespace scan {

namespace {

struct Ring {
    Frame*        slots;
    size_t        capacity;
    volatile size_t head;
    volatile size_t tail;
    volatile uint32_t dropped;
    portMUX_TYPE  mux;
};

Ring ring_pcap = { nullptr, 0, 0, 0, 0, portMUX_INITIALIZER_UNLOCKED };
Ring ring_dash = { nullptr, 0, 0, 0, 0, portMUX_INITIALIZER_UNLOCKED };

// Written by the NimBLE callback task, read (and for the pps window, reset)
// from the dashboard task and from loop() via CMD:STATUS. Atomics rather than
// volatile: a plain read-modify-write across those tasks loses increments.
std::atomic<uint32_t> g_total       {0};
std::atomic<uint32_t> g_this_sec    {0};
std::atomic<uint32_t> g_per_sec     {0};
std::atomic<uint32_t> g_last_pps_ms {0};
std::atomic<uint32_t> g_frame_idx   {0};

// `fallback_slot_count` is what gets allocated (from internal SRAM) if the
// PSRAM attempt at `slot_count` fails -- psramFound() only reports that PSRAM
// hardware exists, not that a specific contiguous block is still free (e.g.
// session_pcap::init() already claims up to 6MB of it before scan::init()
// runs), so this path is reachable with PSRAM present. Falling back to the
// same large `slot_count` would commit the PSRAM-sized buffer to internal
// SRAM instead -- SRAM shared with the WiFi/BT stacks and AsyncTCP/ArduinoJson
// buffers -- defeating the whole point of sizing the no-PSRAM case smaller.
bool ring_alloc(Ring& r, size_t slot_count, size_t fallback_slot_count, bool prefer_psram) {
    r.head = 0; r.tail = 0; r.dropped = 0;
    if (prefer_psram && psramFound()) {
        size_t bytes = slot_count * sizeof(Frame);
        r.slots = (Frame*)ps_malloc(bytes);
        if (r.slots) {
            r.capacity = slot_count;
            return true;
        }
    }
    r.capacity = fallback_slot_count;
    r.slots = (Frame*)malloc(fallback_slot_count * sizeof(Frame));
    return r.slots != nullptr;
}

inline size_t ring_next(const Ring& r, size_t i) {
    const size_t n = i + 1;
    return n == r.capacity ? 0 : n;      // no modulo: capacity is runtime, so % is a real divide
}

// A Frame is 284 bytes but a legacy advert uses ~60 of them. Both copies below
// run inside a spinlock with interrupts off, into or out of PSRAM, twice per
// advert -- so copy the header plus payload_len, not the whole struct.
inline size_t frame_bytes(const Frame& f) {
    return offsetof(Frame, payload) + f.payload_len;
}

void ring_push(Ring& r, const Frame& f) {
    const size_t n = frame_bytes(f);
    // Task-context variant, matching ring_pop()/clear_ring() below -- onResult()
    // runs on the NimBLE host task, not an ISR. The _ISR variant only takes the
    // spinlock and leaves interrupts enabled, so a preemption here could hand
    // the core to a task that then blocks on the same mux via portENTER_CRITICAL
    // (which does mask interrupts): that task spins forever since the holder it
    // is waiting on cannot run again until this core services an interrupt --
    // and interrupts are exactly what it just disabled. Same spinlock, one
    // variant, both sides.
    portENTER_CRITICAL(&r.mux);
    size_t next_head = ring_next(r, r.head);
    if (next_head == r.tail) {
        r.tail = ring_next(r, r.tail);
        r.dropped++;
    }
    memcpy(&r.slots[r.head], &f, n);
    r.head = next_head;
    portEXIT_CRITICAL(&r.mux);
}

bool ring_pop(Ring& r, Frame* out) {
    bool got = false;
    portENTER_CRITICAL(&r.mux);
    if (r.tail != r.head) {
        const Frame& s = r.slots[r.tail];
        memcpy(out, &s, frame_bytes(s));
        r.tail = ring_next(r, r.tail);
        got = true;
    }
    portEXIT_CRITICAL(&r.mux);
    return got;
}

// NimBLE HCI advType (from advertisement report) → wire LL PDU type.
uint8_t map_hci_advtype_to_ll(uint8_t hci) {
    switch (hci) {
        case 0: return LL_ADV_IND;         // BLE_HCI_ADV_TYPE_ADV_IND
        case 1: return LL_ADV_DIRECT_IND;  // BLE_HCI_ADV_TYPE_ADV_DIRECT_IND_HD
        case 2: return LL_ADV_SCAN_IND;    // BLE_HCI_ADV_TYPE_ADV_SCAN_IND
        case 3: return LL_ADV_NONCONN_IND; // BLE_HCI_ADV_TYPE_ADV_NONCONN_IND
        case 4: return LL_SCAN_RSP;        // BLE_HCI_ADV_TYPE_SCAN_RSP
        // Anything else (an extended-advertising event type, say) is not a
        // legacy PDU we can name. Report it as unknown -- the old default of
        // LL_ADV_IND wrote a PDU type into the PCAP that was never on air.
        default: return LL_UNKNOWN;
    }
}

// Random address subtype is encoded in the top two bits of MSB (byte 5, per BLE spec).
// NimBLE surfaces the address in the same byte order the user expects (byte 5 is MSB).
uint8_t classify_random_addr(const uint8_t addr[6]) {
    uint8_t hi2 = (addr[5] >> 6) & 0x03;
    switch (hi2) {
        case 0b00: return ADDR_RANDOM_NRP;
        case 0b01: return ADDR_RANDOM_RPA;
        case 0b11: return ADDR_RANDOM_STATIC;
        default:   return ADDR_RANDOM_STATIC; // 0b10 reserved; treat as static
    }
}

uint8_t ftbit_for_ll(uint8_t ll_pdu_type) {
    switch (ll_pdu_type) {
        case LL_ADV_IND:         return config::FT_ADV_IND;
        case LL_ADV_DIRECT_IND:  return config::FT_ADV_DIRECT;
        case LL_ADV_NONCONN_IND: return config::FT_ADV_NONCONN;
        case LL_SCAN_RSP:        return config::FT_SCAN_RSP;
        case LL_ADV_SCAN_IND:    return config::FT_ADV_SCAN_IND;
        default:                 return 0xFF;
    }
}

class Cb : public NimBLEAdvertisedDeviceCallbacks {
    void onResult(NimBLEAdvertisedDevice* dev) override {
        if (!dev) return;

        // Filter early — cheap byte checks. Advert-type gate.
        uint8_t ll = map_hci_advtype_to_ll(dev->getAdvType());
        uint8_t ft = config::get().ft_mask;
        uint8_t typebit = ftbit_for_ll(ll);
        if (typebit != 0xFF && (ft & typebit) == 0) return;

        NimBLEAddress a = dev->getAddress();
        uint8_t addr_type_raw = a.getType();

        // NimBLE stores the address with m_address[5] = MSB and m_address[0] = LSB
        // (verified against library's toString(): it prints m_address[5..0]).
        // Match that convention for the Frame — addr[5] is MSB, addr[0] is LSB.
        // The on-wire LE-LL AA is transmitted LSB first, so nordic_pcap writes
        // addr[0..5] in stored order (correctly LSB first).
        const uint8_t* nat = a.getNative();
        uint8_t addr[6];
        memcpy(addr, nat, 6);

        uint8_t addr_type;
        if (addr_type_raw == 0 || addr_type_raw == 2) {
            addr_type = ADDR_PUBLIC;
            if ((ft & config::FT_ADDR_PUBLIC) == 0) return;
        } else if (addr_type_raw == 1 || addr_type_raw == 3) {
            addr_type = classify_random_addr(addr);
            if ((ft & config::FT_ADDR_RANDOM) == 0) return;
        } else {
            addr_type = ADDR_UNKNOWN;
        }

        Frame f;
        f.idx  = g_frame_idx.fetch_add(1, std::memory_order_relaxed) + 1;
        struct timeval tv;
        gettimeofday(&tv, nullptr);
        f.ts_sec  = (uint32_t)tv.tv_sec;
        f.ts_usec = (uint32_t)tv.tv_usec;
        f.channel = 0xFF;                     // NimBLE doesn't expose per-advert channel
        f.rssi    = (int8_t)dev->getRSSI();
        f.tx_power = dev->haveTXPower() ? (int8_t)dev->getTXPower() : INT8_MIN;
        f.ll_pdu_type = ll;
        f.addr_type   = addr_type;
        memcpy(f.addr, addr, 6);

        size_t plen = dev->getPayloadLength();
        if (plen > MAX_PAYLOAD) plen = MAX_PAYLOAD;
        f.payload_len = (uint16_t)plen;
        if (plen > 0) memcpy(f.payload, dev->getPayload(), plen);

        ring_push(ring_pcap, f);
        ring_push(ring_dash, f);

        g_total.fetch_add(1, std::memory_order_relaxed);
        g_this_sec.fetch_add(1, std::memory_order_relaxed);
    }
};

Cb g_cb;

void start_scan() {
    NimBLEScan* s = NimBLEDevice::getScan();
    s->stop();
    s->setActiveScan(false);           // passive — never emit SCAN_REQ
    // One snapshot, not two separate config::get() calls: a config write
    // landing between them could otherwise hand NimBLE a window/interval pair
    // that never existed together in any single config generation, violating
    // the half-interval coexistence invariant clamp() enforces on every write.
    const config::Config sc = config::get();
    s->setInterval(sc.scan_interval_ms);
    s->setWindow(sc.scan_window_ms);
    s->setDuplicateFilter(false);      // capture every advert, even repeats
    // Do not retain results. NimBLE's default (0xFF) disables its own cap and
    // heap-allocates a NimBLEAdvertisedDevice for every distinct address for
    // the life of the scan -- and this scan never ends. With RPAs rotating on
    // every phone and tag in range that is an unbounded leak; the sniffer
    // slowly eats its heap and dies. With 0, each device is created, handed
    // to onResult() (which copies what it needs), then freed.
    s->setMaxResults(0);
    s->setAdvertisedDeviceCallbacks(&g_cb, /*wantDuplicates=*/true);
    s->start(0, nullptr, false);
}

} // namespace

bool init() {
    bool have_psram = psramFound();
    // psramFound() means PSRAM hardware exists, not that a ~90KB contiguous
    // block is still free -- session_pcap::init() runs first and can already
    // have claimed most of it. ring_alloc() falls back to the smaller
    // no-PSRAM slot counts (not the PSRAM-sized ones) if ps_malloc() fails.
    if (!ring_alloc(ring_pcap, 256, 16, have_psram)) return false;
    if (!ring_alloc(ring_dash, 64,  8,  have_psram)) return false;

    NimBLEDevice::init("");
    // No setPower — passive scan never TXes, so TX-power tuning is moot.
    start_scan();
    return true;
}

void apply_scan_params() {
    start_scan();
}

bool pop_pcap(Frame* out)      { return ring_pop(ring_pcap, out); }
bool pop_dashboard(Frame* out) { return ring_pop(ring_dash, out); }

uint32_t total_adverts() { return g_total.load(std::memory_order_relaxed); }
uint32_t dropped_pcap()  { return ring_pcap.dropped; }
uint32_t dropped_dash()  { return ring_dash.dropped; }

uint32_t adverts_per_sec() {
    const uint32_t now  = millis();
    uint32_t       last = g_last_pps_ms.load(std::memory_order_relaxed);
    // Two tasks poll this: the dashboard status tick and CMD:STATUS from
    // loop(). Only the caller that wins the compare-exchange rolls the window,
    // so a second caller can no longer zero a window it did not open (which
    // made the dashboard read 0 pps whenever a script polled CMD:STATUS).
    const uint32_t elapsed = now - last;
    if (elapsed >= 1000 &&
        g_last_pps_ms.compare_exchange_strong(last, now, std::memory_order_relaxed)) {
        // Divide by the window that actually elapsed, not by an assumed one
        // second. Nothing guarantees this is polled at 1 Hz -- with no
        // dashboard client connected the first CMD:STATUS after a quiet spell
        // reported a whole minute of adverts as one second (observed: 2619
        // pps against a true rate of ~45).
        const uint64_t count = g_this_sec.exchange(0, std::memory_order_relaxed);
        g_per_sec.store((uint32_t)(count * 1000u / elapsed), std::memory_order_relaxed);
    }
    return g_per_sec.load(std::memory_order_relaxed);
}

void clear_ring() {
    portENTER_CRITICAL(&ring_pcap.mux);
    ring_pcap.head = ring_pcap.tail = 0; ring_pcap.dropped = 0;
    portEXIT_CRITICAL(&ring_pcap.mux);
    portENTER_CRITICAL(&ring_dash.mux);
    ring_dash.head = ring_dash.tail = 0; ring_dash.dropped = 0;
    portEXIT_CRITICAL(&ring_dash.mux);
}

} // namespace scan
