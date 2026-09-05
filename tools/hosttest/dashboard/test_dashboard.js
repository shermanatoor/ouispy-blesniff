// Loads the ACTUAL dashboard HTML/JS (extracted byte-for-byte from
// src/dashboard_html.h) into a real jsdom DOM and drives it like a browser:
// synthesize {i,t,c,r,y,a,m,l,f,n,s,u,v} packets through the real WebSocket
// message handler, click real buttons, read real DOM state back. No stubs
// of the logic under test -- only WebSocket/fetch are replaced, because
// jsdom has no network.
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

// Extract the live HTML/JS straight out of the firmware source -- this test
// is only meaningful if it exercises exactly what gets flashed to the
// device, not a copy that can drift out of sync with it.
const SRC = path.join(__dirname, '..', '..', '..', 'src', 'dashboard_html.h');
const cpp = fs.readFileSync(SRC, 'utf8');
const m = cpp.match(/R"HTML\(([\s\S]*?)\)HTML";/);
if (!m) throw new Error('could not find the R"HTML(...)HTML" literal in ' + SRC);
const html = m[1];

let fails = 0, passes = 0;
function check(name, cond, detail) {
    if (cond) { passes++; console.log('PASS ', name); }
    else { fails++; console.log('FAIL ', name, detail !== undefined ? ':: ' + detail : ''); }
}

class FakeWS {
    constructor(url) { this.url = url; this.readyState = 1; FakeWS.last = this; }
    send() {}
    close() {}
}

async function main() {
    // The dashboard's inline <script> runs synchronously as jsdom parses the
    // document (runScripts: 'dangerously'), so WebSocket/fetch/etc must be
    // stubbed via beforeParse -- setting them after `new JSDOM(...)` returns
    // is too late, the script has already called the real (missing) ones.
    const dom = new JSDOM(html, {
        url: 'http://192.168.4.1/', runScripts: 'dangerously',
        resources: 'usable', pretendToBeVisual: true,
        beforeParse(window) {
            window.WebSocket = FakeWS;
            window.fetch = () => Promise.reject(new Error('no network in test'));
            window.confirm = () => true;
            window.URL.createObjectURL = () => 'blob:test';
            window.URL.revokeObjectURL = () => {};
        },
    });
    const { window } = dom;
    // jsdom doesn't implement scrollTop/scrollHeight layout; make them writable
    // no-ops so stickBottom()/setFollow() don't throw.
    Object.defineProperty(window.HTMLElement.prototype, 'scrollTop', { value: 0, writable: true });
    Object.defineProperty(window.HTMLElement.prototype, 'scrollHeight', { value: 0, writable: true });
    Object.defineProperty(window.HTMLElement.prototype, 'clientHeight', { value: 0, writable: true });

    await new Promise(r => setTimeout(r, 50));   // let the inline script's IIFE run

    const doc = window.document;
    const $ = (id) => doc.getElementById(id);

    // ---- helper: feed a WS 'pkts' batch straight through the real handler ----
    function sendPkts(packets) {
        FakeWS.last.onmessage({ data: JSON.stringify({ type: 'pkts', p: packets }) });
    }
    function sendStatus(fields) {
        FakeWS.last.onmessage({ data: JSON.stringify(Object.assign({ type: 'status' }, fields)) });
    }
    async function flush() {
        // scheduleFlush() uses requestAnimationFrame; jsdom's rAF runs on a timer.
        await new Promise(r => setTimeout(r, 50));
    }

    // ================= vendor matching + confidence tier =================
    // A registry-confident Axon hit: public MAC on the real Axon OUI.
    sendPkts([{ i: 1, t: 0, c: 37, r: -50, y: 'ADV_IND', a: 'pub', m: '00:25:df:11:22:33', l: 10 }]);
    await flush();
    {
        const tr = doc.querySelector('#rows tr');
        check('confident vendor match renders a tag', !!tr.querySelector('.tag.vendor'), tr && tr.innerHTML);
        check('confident match is NOT tagged weak', !tr.querySelector('.tag.vendor.weak'));
        check('confident match sets dataset.hit=1', tr.dataset.hit === '1');
        check('confident match sets dataset.weak=0', tr.dataset.weak === '0');
        check('vendor tag has no "?" suffix', !tr.querySelector('.tag.vendor').textContent.includes('?'));
    }

    // A broad-tier-only Flock hit: public MAC on an Espressif OUI in Flock's
    // ouisBroad, no name/cid/svc corroboration. This is the exact shape of
    // the false positive this session's Flock work was written to fix.
    $('rows').innerHTML = '';
    sendPkts([{ i: 2, t: 0, c: 37, r: -50, y: 'ADV_IND', a: 'pub', m: 'a4:cf:12:aa:bb:cc', l: 10 }]);
    await flush();
    {
        const tr = doc.querySelector('#rows tr');
        check('broad-only match still renders (confidentOnly off by default)', !!tr && tr.innerHTML.includes('FLOCK'));
        check('broad-only match IS tagged weak', !!tr.querySelector('.tag.vendor.weak'));
        check('broad-only match shows "FLOCK?" not "FLOCK"', tr.querySelector('.tag.vendor').textContent === 'FLOCK?');
        check('broad-only match still counted as hit while confidentOnly is off',
              tr.dataset.hit === '1', 'hit=' + tr.dataset.hit);
        check('broad-only match flagged weak=1', tr.dataset.weak === '1');
    }

    // Same Espressif OUI, but on a RANDOM address -- must not match at all,
    // confident or broad, since only public addresses carry a real OUI.
    $('rows').innerHTML = '';
    sendPkts([{ i: 3, t: 0, c: 37, r: -50, y: 'ADV_IND', a: 'rnd-rpa', m: 'a4:cf:12:aa:bb:cc', l: 10 }]);
    await flush();
    {
        const tr = doc.querySelector('#rows tr');
        check('random-address OUI does not match any vendor (no OUI on random addrs)',
              tr.dataset.hit === '0' && !tr.innerHTML.includes('tag vendor'), tr.innerHTML);
    }

    // A confident match on vendor A must outrank a broad match on vendor B
    // for the same packet. Use a Flock-broad OUI (a4:cf:12, Espressif) but
    // give the packet an Axon company ID -- Axon should win, not FLOCK?.
    $('rows').innerHTML = '';
    sendPkts([{ i: 4, t: 0, c: 37, r: -50, y: 'ADV_IND', a: 'pub', m: 'a4:cf:12:aa:bb:cc',
               u: '034D', v: 'Axon/TASER', l: 10 }]);
    await flush();
    {
        const tr = doc.querySelector('#rows tr');
        const tag = tr.querySelector('.tag.vendor');
        check('confident match on vendor B outranks broad match on vendor A',
              tag && tag.textContent === 'AXON', tag && tag.textContent);
    }

    // ---- Confident-only toggle: newly arriving weak matches stop counting ----
    $('rows').innerHTML = '';
    $('statHits').textContent = '0';
    $('confidentOnly').checked = true;
    $('confidentOnly').dispatchEvent(new window.Event('change'));
    sendPkts([{ i: 5, t: 0, c: 37, r: -50, y: 'ADV_IND', a: 'pub', m: 'a4:cf:12:aa:bb:cc', l: 10 }]);
    await flush();
    {
        const tr = doc.querySelector('#rows tr');
        check('Confident-only: broad match no longer counted as a hit',
              tr.dataset.hit === '0', 'hit=' + tr.dataset.hit);
        check('Confident-only: statHits stayed at 0', $('statHits').textContent === '0');
        check('Confident-only: vendor tag suppressed entirely', !tr.innerHTML.includes('tag vendor'));
    }
    $('confidentOnly').checked = false;
    $('confidentOnly').dispatchEvent(new window.Event('change'));

    // ================= chip filter: AND across groups, OR within =================
    $('rows').innerHTML = '';
    sendPkts([
        { i: 10, t: 0, c: 37, r: -50, y: 'ADV_IND',     a: 'pub',     m: '11:22:33:44:55:01', l: 5 },
        { i: 11, t: 0, c: 37, r: -50, y: 'ADV_NONCONN', a: 'pub',     m: '11:22:33:44:55:02', l: 5 },
        { i: 12, t: 0, c: 37, r: -50, y: 'ADV_IND',     a: 'rnd-rpa', m: '11:22:33:44:55:03', l: 5 },
    ]);
    await flush();
    check('3 rows rendered before any chip filter', doc.querySelectorAll('#rows tr').length === 3);

    doc.querySelector('.chip[data-key="adv_ind"]').dispatchEvent(new window.Event('click', { bubbles: true }));
    {
        const shown = [...doc.querySelectorAll('#rows tr')].filter(tr => tr.style.display !== 'none');
        check('type=ADV_IND chip alone shows rows 10 and 12, hides 11',
              shown.length === 2 && shown.every(tr => tr.dataset.type === 'adv_ind'),
              shown.map(tr => tr.dataset.type).join(','));
    }
    doc.querySelector('.chip[data-key="a_pub"]').dispatchEvent(new window.Event('click', { bubbles: true }));
    {
        // ADV_IND (type group) AND pub (addr group) -- intersection is row 10 only.
        const shown = [...doc.querySelectorAll('#rows tr')].filter(tr => tr.style.display !== 'none');
        check('ADV_IND + Public together = intersection (row 10 only), not the union',
              shown.length === 1 && shown[0].dataset.atype === 'pub' && shown[0].dataset.type === 'adv_ind',
              shown.map(tr => tr.dataset.addr).join(','));
    }
    // clear chips for subsequent tests
    $('clearChipsBtn').dispatchEvent(new window.Event('click', { bubbles: true }));
    check('Clear all chips restores all 3 rows',
          [...doc.querySelectorAll('#rows tr')].filter(tr => tr.style.display !== 'none').length === 3);

    // ================= free-text filter =================
    $('filter').value = 'addr:44:55:02';
    $('filter').dispatchEvent(new window.Event('input'));
    {
        const shown = [...doc.querySelectorAll('#rows tr')].filter(tr => tr.style.display !== 'none');
        check('addr: filter isolates the matching row', shown.length === 1 && shown[0].dataset.addr.includes('44:55:02'));
    }
    $('filter').value = '';
    $('filter').dispatchEvent(new window.Event('input'));

    // ================= session state machine (client-side only) =================
    check('boots IDLE with RECORD enabled', $('btnRecord').disabled === false && $('sessBadgeTxt').textContent === 'IDLE');
    sendStatus({ state: 'recording' });
    check('status tick -> RECORDING relabels/disables correctly',
          $('btnRecord').disabled === true && $('btnPause').disabled === false && $('btnStop').disabled === false);
    sendStatus({ state: 'paused' });
    check('status tick -> PAUSED shows RESUME label',
          $('btnRecord').innerHTML.includes('RESUME') && $('btnRecord').disabled === false);
    // The actual regression this session fixed: clicking Record from PAUSED
    // must POST /api/session/resume, not /record (which wipes the ring).
    {
        let posted = null;
        window.fetch = (url) => { posted = url; return Promise.resolve({ ok: true }); };
        $('btnRecord').dispatchEvent(new window.Event('click', { bubbles: true }));
        check('Record button from PAUSED posts /api/session/resume (not /record)',
              posted === '/api/session/resume', posted);
    }
    sendStatus({ state: 'stopped' });
    check('status tick -> STOPPED enables Save, shows RE-RECORD',
          $('btnSavePcap').disabled === false && $('btnRecord').innerHTML.includes('RE-RECORD'));
    sendStatus({ state: 'idle' });

    // ================= drop counter includes dropped_ws =================
    sendStatus({ dropped_pcap: 1, dropped_dash: 2, dropped_ws: 3 });
    check('Drop stat sums pcap+dash+ws drop counters', $('statDrop').textContent === '6', $('statDrop').textContent);

    // ================= window/interval clamp warning mirrors firmware =================
    // Firmware: max_window_for(interval) = max(10, floor(interval*50/100)).
    $('scanInt').value = '200';
    $('scanWin').value = '101';   // just above half of 200 (100) -> should warn
    $('scanWin').dispatchEvent(new window.Event('input'));
    check('winWarn shows when window exceeds half the interval',
          $('winWarn').style.display !== 'none');
    $('scanWin').value = '100';   // exactly half -> should NOT warn
    $('scanWin').dispatchEvent(new window.Event('input'));
    check('winWarn hidden when window equals half the interval',
          $('winWarn').style.display === 'none');

    // ================= ftmask checkbox round-trip, via the real load path ====
    // 0x61 = ADV_IND(0x01) + Public(0x20) + Random(0x40) -- the exact
    // "re-opened address + type group" shape from the H8b regression test.
    // Drives it through loadConfig() (real GET /api/config handler), not a
    // reach into the IIFE's private applyFtmask.
    window.fetch = () => Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ scan_win: 30, scan_int: 100, ftmask: 0x61,
                                      ap_ssid: 'x', ap_pass: 'sniffuntothem' }),
    });
    $('btnDiscard').dispatchEvent(new window.Event('click', { bubbles: true }));
    await flush();
    check('loadConfig(ftmask=0x61): ADV_IND checked', $('ftAdvInd').checked === true);
    check('loadConfig(ftmask=0x61): ADV_DIRECT unchecked', $('ftAdvDirect').checked === false);
    check('loadConfig(ftmask=0x61): Public checked', $('ftAddrPub').checked === true);
    check('loadConfig(ftmask=0x61): Random checked', $('ftAddrRnd').checked === true);

    // The btnSave echo path: server normalizes an emptied group back open and
    // echoes the real stored mask -- checkboxes must reflect what was echoed,
    // not what was requested. This is the H8b/H8c fix from PR #2.
    window.fetch = (url, opts) => Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ ok: true, scan_win: 30, scan_int: 100, ftmask: 0x61 }),
    });
    // Uncheck everything in the address group to send ftmask with addr bits clear.
    $('ftAddrPub').checked = false; $('ftAddrRnd').checked = false;
    $('btnSave').dispatchEvent(new window.Event('click', { bubbles: true }));
    await flush();
    check("btnSave echo: server-normalized ftmask re-checks the address group (was: unchecked despite firmware capturing everything)",
          $('ftAddrPub').checked === true && $('ftAddrRnd').checked === true);

    // ================= CSV export honours the active filter =================
    $('rows').innerHTML = '';
    sendPkts([
        { i: 20, t: 0, c: 37, r: -50, y: 'ADV_IND',     a: 'pub', m: 'aa:bb:cc:dd:ee:01', l: 5 },
        { i: 21, t: 0, c: 37, r: -50, y: 'ADV_NONCONN', a: 'pub', m: 'aa:bb:cc:dd:ee:02', l: 5 },
    ]);
    await flush();
    doc.querySelector('.chip[data-key="adv_ind"]').dispatchEvent(new window.Event('click', { bubbles: true }));
    {
        let blobText = null;
        const OrigBlob = window.Blob;
        window.Blob = function (parts, opts) { blobText = parts[0]; return new OrigBlob(parts, opts); };
        $('snapBtn').dispatchEvent(new window.Event('click', { bubbles: true }));
        window.Blob = OrigBlob;
        const rowsInCsv = blobText.trim().split('\n').length - 1;   // minus header
        check('CSV export contains only the filtered (visible) row, not both',
              rowsInCsv === 1 && blobText.includes('ee:01') && !blobText.includes('ee:02'),
              blobText);
    }
    $('clearChipsBtn').dispatchEvent(new window.Event('click', { bubbles: true }));

    console.log('\n==== %d passed, %d failed ====', passes, fails);
    process.exit(fails ? 1 : 0);
}

main().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
