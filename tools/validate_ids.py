"""Cross-check the vendor tables against the IEEE and Bluetooth SIG registries.

    python tools/validate_ids.py            # validate what the source lists
    python tools/validate_ids.py --search   # also list registry entries the tables lack

Pulls the IEEE MA-L (OUI) registry and the Bluetooth SIG company identifiers
and 16-bit member UUIDs, then checks every entry in:

  * VENDORS in src/dashboard_html.h       -- ouis / cids / svcs
  * mfr_shortname() in src/text_summary.cpp

Exit status 1 if any listed identifier is unassigned or assigned to an
organization whose name does not match the vendor it is filed under.
Run before editing either table.
"""
import csv
import io
import os
import re
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(ROOT, ".ids-cache")
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0 Safari/537.36",
      "Accept": "*/*"}

SOURCES = {
    "oui.csv": "https://standards-oui.ieee.org/oui/oui.csv",
    "company_identifiers.yaml":
        "https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml",
    "member_uuids.yaml":
        "https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/uuids/member_uuids.yaml",
}

# `ouisBroad` in the source is the field-observed tier: radio-module makers and
# unattributed prefixes seen on the vendor's hardware. They are reported as
# "obs" and never failed -- the point of the tier is that they do NOT match the
# registry. `ouis` must stay registry-clean, so it is checked strictly.
OBSERVED_CID = {
    "dji":    {0x0BF3},          # observed; registry says PONE Biometrics
    "parrot": {0x004D},          # observed; registry says Staccato
    "flock":  {0x09C8},          # XUNTONG -- the battery supplier, not Flock itself
}
# Proprietary service UUIDs a vendor advertises without registering them with
# the SIG. Absent from member_uuids.yaml by definition, so exempt from the
# assignment check -- but they must still be vendor-specific enough to identify.
OBSERVED_UUID = {
    "flock": {0x3100, 0x3200, 0x3300, 0x3400, 0x3500},   # Raven gunshot detector
}
OBSERVED_MFR = {"DJI (observed)", "Parrot (observed)"}

# What a registry organization name must contain to count as "this vendor".
VENDOR_ORG = {
    "ring":   r"\bring (llc|solutions)\b",
    "axon":   r"axon enterprise|taser",
    "flock":  r"flock safety",
    "dji":    r"\bdji\b",
    "parrot": r"\bparrot\b",
    "skydio": r"skydio",
    "meta":   r"meta platforms|facebook|oculus|luxottica|essilor",
}
MFR_ORG = {  # shortname -> registry name fragment
    "Apple": "apple", "Microsoft": "microsoft", "Google": "google", "Samsung": "samsung",
    "Amazon": "amazon", "Xiaomi": "xiaomi", "Garmin": "garmin", "Sonos": "sonos",
    "Bose": "bose", "GoPro": "gopro", "Nordic": "nordic", "Cypress": "cypress",
    "Espressif": "espressif", "Broadcom": "broadcom", "Nokia": "nokia",
    "Anhui Huami": "huami", "Ruuvi": "ruuvi", "Axon/TASER": "taser", "Meta": "meta platforms",
    "Meta (Reality Labs)": "meta platforms", "Luxottica (Meta/Ray-Ban)": "luxottica",
    "DJI": "dji", "Parrot Automotive": "parrot",
}


def fetch(name):
    os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, name)
    if not os.path.exists(path):
        print("fetching", name)
        data = urllib.request.urlopen(urllib.request.Request(SOURCES[name], headers=UA), timeout=120).read()
        open(path, "wb").write(data)
    return io.open(path, encoding="utf-8", errors="replace").read()


def load_registries():
    oui = {}
    for row in csv.DictReader(io.StringIO(fetch("oui.csv"))):
        oui[row["Assignment"].strip().lower()] = row["Organization Name"].strip()
    yaml_pairs = lambda text, key: {
        (int(m.group(1), 16) if m.group(1).startswith("0x") else int(m.group(1))): m.group(2)
        for m in re.finditer(r"-\s*%s:\s*(0x[0-9A-Fa-f]+|\d+)\s*\n\s*name:\s*[\"']?(.*?)[\"']?\s*\n" % key, text)}
    cid = yaml_pairs(fetch("company_identifiers.yaml"), "value")
    uuid = yaml_pairs(fetch("member_uuids.yaml"), "uuid")
    return oui, cid, uuid


def load_tables():
    html = io.open(os.path.join(ROOT, "src", "dashboard_html.h"), encoding="utf-8").read()
    blk = html[html.index("const VENDORS = ["):html.index("];", html.index("const VENDORS = ["))]
    vendors = {}
    for m in re.finditer(r"id:'(\w+)'.*?ouis:\[(.*?)\](.*?)cids:\[(.*?)\].*?svcs:\[(.*?)\]", blk, re.S):
        # arrays carry "// registry: ..." / "// observed" annotations
        strip = lambda x: re.sub(r"//.*", "", x)   # . never matches a newline
        lst = lambda x: [t.strip().strip("'") for t in strip(x).split(",") if t.strip()]
        mid = m.group(3)
        bm = re.search(r"ouisBroad:\[(.*?)\]", mid, re.S)
        vendors[m.group(1)] = {"ouis": lst(m.group(2)),
                               "ouisBroad": lst(bm.group(1)) if bm else [],
                               "cids": lst(m.group(4)), "svcs": lst(m.group(5))}
    cpp = io.open(os.path.join(ROOT, "src", "text_summary.cpp"), encoding="utf-8").read()
    mfr = dict(re.findall(r'case 0x([0-9A-Fa-f]{4}): return "([^"]+)";', cpp))
    return vendors, mfr


def main():
    search = "--search" in sys.argv
    oui, cid, uuid = load_registries()
    vendors, mfr = load_tables()
    bad = 0

    print("== VENDORS ==")
    for v, d in vendors.items():
        pat = VENDOR_ORG.get(v, v)
        for o in d["ouis"]:
            key = o.replace(":", "").lower()
            org = oui.get(key)
            ok = bool(org and re.search(pat, org, re.I))
            obs = False
            bad += not (ok or obs)
            tag = "ok " if ok else ("obs" if obs else "BAD")
            print("  %s %-7s OUI %s -> %s" % (tag, v, o, org or "UNASSIGNED"))
        for o in d["ouisBroad"]:
            org = oui.get(o.replace(":", "").lower())
            print("  obs %-7s OUI %s -> %s  (broad tier)" % (v, o, org or "UNASSIGNED"))
        for c in d["cids"]:
            org = cid.get(int(c, 16))
            ok = bool(org and re.search(pat + r"|amazon", org, re.I))
            obs = int(c, 16) in OBSERVED_CID.get(v, set())
            bad += not (ok or obs)
            tag = "ok " if ok else ("obs" if obs else "BAD")
            print("  %s %-7s CID 0x%s -> %s" % (tag, v, c.upper(), org or "UNASSIGNED"))
        for u in d["svcs"]:
            org = uuid.get(int(u, 16))
            ok = bool(org and re.search(pat, org, re.I))
            obs = int(u, 16) in OBSERVED_UUID.get(v, set())
            bad += not (ok or obs)
            tag = "ok " if ok else ("obs" if obs else "BAD")
            print("  %s %-7s UUID 0x%s -> %s%s"
                  % (tag, v, u.upper(), org or "UNASSIGNED", "  (proprietary)" if obs else ""))

    print("== mfr_shortname ==")
    for h, name in mfr.items():
        org = cid.get(int(h, 16))
        frag = MFR_ORG.get(name, name.split("/")[0].split(" (")[0].lower())
        ok = bool(org and frag.lower() in org.lower())
        obs = name in OBSERVED_MFR
        bad += not (ok or obs)
        tag = "ok " if ok else ("obs" if obs else "BAD")
        print("  %s 0x%s %-26s -> %s" % (tag, h, name, org or "UNASSIGNED"))

    if search:
        print("== registry entries not listed ==")
        for v, pat in VENDOR_ORG.items():
            have = {o.replace(":", "").lower() for o in vendors.get(v, {}).get("ouis", [])}
            for k, org in sorted(oui.items()):
                if re.search(pat, org, re.I) and k not in have:
                    print("  %-7s OUI %s  %s" % (v, ":".join(k[i:i + 2] for i in (0, 2, 4)), org))
            havec = {int(c, 16) for c in vendors.get(v, {}).get("cids", [])}
            for k, org in sorted(cid.items()):
                if re.search(pat, org, re.I) and k not in havec:
                    print("  %-7s CID 0x%04X  %s" % (v, k, org))
            haveu = {int(u, 16) for u in vendors.get(v, {}).get("svcs", [])}
            for k, org in sorted(uuid.items()):
                if re.search(pat, org, re.I) and k not in haveu:
                    print("  %-7s UUID 0x%04X  %s" % (v, k, org))

    print("\n%s" % ("all identifiers valid (obs = field-observed, not registry-assigned)"
                     if not bad else "%d BAD identifier(s)" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
