# IoT Patch Dataset

Firmware-vulnerability existence-verification datasets and (work-in-progress) patch
artifacts for IoT devices. Each vendor family lives in its own directory.

## D-Link (`dlink/`)

60 D-Link router / IP-camera / access-point firmware targets, each paired with 1-2
CVE candidates, verified at the **binary level**: every verdict is backed by evidence
from static reverse engineering (objdump/strings/readelf) of the exact firmware build,
not merely by version-range matching.

### Status (2026-10-21)

| Metric | Value |
|---|---|
| Targets verified | 30 / 60 (selection rank 1-30) |
| CVE verdicts | 51 (40 confirmed, 1 likely, 10 absent) |
| Targets with ≥1 existing vuln | 27 / 30 |
| Refs archived (NVD record copies) | 41 CVEs |

"Existing" = `confirmed` + `likely`. The remaining 30 targets are queued.

### Verdict levels

| Verdict | Meaning |
|---|---|
| `confirmed` | handler + sink located, full attacker-controlled path (addresses recorded) |
| `likely` | binary + endpoint + handler present, sink not fully provable statically, unpatched |
| `absent` | vulnerable code not in this build (endpoint missing, or provably patched) |
| `version_mismatch` | build outside advisory range |
| `inconclusive` | cannot anchor from advisory description |

### Layout

```
dlink/
├── manifest/
│   ├── cve_candidates_60.csv      # target <-> firmware <-> CVE mapping (60 rows)
│   ├── verified_firmwares.csv     # sha256 + direct vendor download link + size
│   └── dlink_candidate_iterations.json   # candidate replacement history
├── verification/                  # per-target results
│   └── <NN_MODEL>/
│       ├── extract.json           # unpack info: rootfs path, arch, version strings
│       ├── verdict.json           # CVE verdicts with evidence (commands + output)
│       ├── refs.json              # archived reference links for existing vulns
│       └── records/               # CVE record snapshots used
├── cve_records/                   # local NVD record.json copies (31 CVEs)
└── docs/ACCEPTANCE.md             # acceptance criteria and per-target records
```

### Reproducing the firmware set

Firmware binaries are **not** redistributed here (vendor licensing). Every target can
be restored byte-identically from the vendor archive:

```bash
python3 - <<'EOF'
import csv, hashlib, urllib.request, os, sys
for r in csv.DictReader(open("dlink/manifest/verified_firmwares.csv", encoding="utf-8-sig")):
    dest = os.path.join("firmware", r["device_class"], r["base_model"],
                        r["firmware_version"], r["filename"])
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if os.path.isfile(dest) and hashlib.sha256(open(dest,'rb').read()).hexdigest() == r["sha256"]:
        continue
    print("downloading", r["filename"])
    urllib.request.urlretrieve(r["source_link"], dest)
    got = hashlib.sha256(open(dest,'rb').read()).hexdigest()
    if got != r["sha256"]:
        sys.exit(f"sha256 mismatch for {r['filename']}: {got}")
EOF
```

All 60 links (ftp.dlink.de vendor archive) were re-verified alive and size-matched on
2026-10-26; a full-download sample matched the recorded sha256 byte-for-byte.

### Verification methodology

Per target, a three-stage pipeline (`extract -> verify -> refs`) runs as isolated
agents over the unpacked rootfs:

1. **Version gate** — advisory affected range vs. build identity (version strings from
   inside the firmware, region/hardware-revision suffixes honored). Out of range ->
   `version_mismatch`; unclear range -> proceed to code.
2. **Targeted reverse engineering** — locate the advisory-named binary/endpoint via
   string xrefs (IDA-style `sub_XXXXXX` names are never trusted as symbols), walk to
   the sink (`strcpy`/`sprintf`/`system`/...), confirm attacker-controlled parameter
   flow. Negative verdicts require checking companion daemons (IPC-forwarded sinks).
3. **Refs archival** — for confirmed/likely CVEs, store the CVE record and its
   reference links (links only, no page bodies).

Notable dataset property: 10/51 verdicts are `absent` *inside* the advisory's nominal
version range — documented evidence that vendor/NVD affected-version data is
frequently over-broad at the lower bound or under-specified per device generation.

## Roadmap

- [ ] Verify remaining 30 targets
- [ ] Replacement candidates for all-absent targets (03_DIR-300, 13_DWR-921, 24_DCS-7410)
- [ ] Patch artifacts: binary patches + security/functional-equivalence verification
      reports for confirmed vulnerabilities (first pilot: DIR-825 / CVE-2025-10666,
      `sprintf` stack overflow in `sbin/httpd`)

## Provenance & license

- Firmware: obtained from the official D-Link archive (ftp.dlink.de); not
  redistributed — use the reproduction script above.
- CVE records: derived from NVD public data.
- Manifests, verification artifacts and analysis results: produced by the pipeline
  described above; provided as-is for research use.
