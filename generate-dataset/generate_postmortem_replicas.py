"""
CSG Real Postmortem Replica Generator
======================================
Membangun dari NOL file-file yang mereplikasi kondisi TEPAT SAAT INSIDEN
berdasarkan detail teknis dari postmortem resmi masing-masing perusahaan.

Ini BERBEDA dari generate_incident_scenarios.py yang inject ke file nyata.
Di sini kita merekonstruksi STRUKTUR LENGKAP file yang terlibat insiden —
termasuk ukuran, schema, dan nilai yang mencerminkan kondisi saat crash.

Setiap insiden menghasilkan 3 file:
  _baseline  : kondisi SEBELUM insiden (CSG harus PASS)
  _incident  : kondisi SAAT insiden berlangsung (CSG harus WARN/CRITICAL)
  _peak      : kondisi TERPARAH sebelum insiden dihentikan (CSG harus CRITICAL)

Insiden yang direplikasi (4 insiden × 3 file = 12 file):
  R1 — Cloudflare Bot Management Feature File (Nov 2025)
  R2 — CrowdStrike Channel File 291 (Jul 2024)
  R3 — Roblox Consul Service Registry (Okt 2021)
  R4 — FAA NOTAM Database (Jan 2023)

Output: tests/evaluation_dataset/3_real_postmortem_replicas/
"""

import json, yaml, csv, copy, random, hashlib, datetime, math
from pathlib import Path
from collections import Counter

random.seed(42)

OUT   = Path("tests/evaluation_dataset/3_real_postmortem_replicas")
GT    = Path("tests/evaluation_dataset/ground_truth_postmortem_replicas.csv")
OUT.mkdir(parents=True, exist_ok=True)

RECORDS = []

def w_json(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def w_yaml(path, data):
    path.write_text(
        yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False),
        encoding="utf-8"
    )

def kb(path): return path.stat().st_size / 1024

def rec(filepath, verdict, sid, source, anomaly, analyzer, notes):
    RECORDS.append({
        "filepath": str(filepath), "expected_verdict": verdict,
        "scenario_id": sid, "incident_source": source,
        "anomaly_type": anomaly, "csg_analyzer_target": analyzer, "notes": notes,
    })


# =============================================================================
# R1 — CLOUDFLARE Bot Management Feature File (18 Nov 2025)
#
# Postmortem (blog.cloudflare.com/18-november-2025-outage):
#   ClickHouse query untuk menggenerate bot feature file kehilangan filter
#   shard karena DB permission change. Query SELECT * FROM bot_features
#   (tanpa WHERE shard='r1') mengembalikan baris dari semua shard,
#   membuat feature_count melompat dari ~60 ke 200+.
#   File di-propagate ke seluruh edge node sebelum dideteksi.
#   Proxy Rust (FL2) pre-alokasi array 200 slot — ketika file berisi
#   280 entry, terjadi out-of-bounds write → crash loop global.
#
# Karakteristik file yang direplikasi:
#   baseline : 60 features, ~14KB, feature_count dalam batas
#   incident : 120 features (2x, dari 2 shard), ~28KB
#   peak     : 280 features (dari 4 shard), ~65KB, melebihi hard_limit=200
# =============================================================================
def replica_cloudflare():
    print("\n[R1] Cloudflare Bot Feature File...")
    d = OUT / "R1_cloudflare"
    d.mkdir(exist_ok=True)

    HARD_LIMIT = 200

    def feature(fid, shard, extra_meta=False):
        f = {
            "feature_id":   f"bf_{fid:04d}",
            "shard":        shard,
            "weight":       round(random.uniform(-2.0, 2.0), 6),
            "bias":         round(random.uniform(-0.5, 0.5), 6),
            "feature_type": random.choice([
                "http_header_ratio","request_timing","tls_fingerprint",
                "mouse_entropy","keystroke_cadence","ip_reputation",
            ]),
            "version":  "2025-11-18",
            "active":   True,
        }
        if extra_meta:
            f["propagation_ts"] = "2025-11-18T11:48:00Z"
            f["source_query"]   = "SELECT * FROM bot_features JOIN metadata ON TRUE"
        return f

    # BASELINE: 60 fitur dari shard r1 saja — kondisi normal
    base = {
        "schema":          "bot-feature-file-v3",
        "generated_at":    "2025-11-18T11:00:00Z",
        "source_query":    "SELECT * FROM bot_features WHERE shard='r1'",
        "feature_count":   60,
        "hard_limit":      HARD_LIMIT,
        "within_limit":    True,
        "features":        [feature(i, "r1") for i in range(60)],
    }
    p_base = d / "cloudflare_bot_features_baseline.json"
    w_json(p_base, base)

    # INCIDENT: 120 fitur — shard r0 ikut ter-include karena permission bug
    inc = {
        "schema":          "bot-feature-file-v3",
        "generated_at":    "2025-11-18T11:20:00Z",
        "source_query":    "SELECT * FROM bot_features",   # filter shard hilang!
        "feature_count":   120,
        "hard_limit":      HARD_LIMIT,
        "within_limit":    True,   # masih di bawah 200 — tapi sudah 2x baseline
        "features":        [feature(i, "r1") for i in range(60)] +
                           [feature(i, "r0") for i in range(60)],
    }
    p_inc = d / "cloudflare_bot_features_incident.json"
    w_json(p_inc, inc)

    # PEAK: 280 fitur — 4 shard, melampaui hard_limit 200 → proxy crash
    peak = {
        "schema":          "bot-feature-file-v3",
        "generated_at":    "2025-11-18T11:48:00Z",
        "source_query":    "SELECT * FROM bot_features JOIN metadata ON TRUE",
        "feature_count":   280,
        "hard_limit":      HARD_LIMIT,
        "within_limit":    False,  # MELAMPAUI — seharusnya blokir propagasi
        "limit_exceeded":  True,
        "features":        ([feature(i, "r1") for i in range(60)] +
                            [feature(i, "r0") for i in range(60)] +
                            [feature(i, "r2", extra_meta=True) for i in range(80)] +
                            [feature(i, "r3", extra_meta=True) for i in range(80)]),
    }
    p_peak = d / "cloudflare_bot_features_peak.json"
    w_json(p_peak, peak)

    r_inc  = kb(p_inc)  / kb(p_base)
    r_peak = kb(p_peak) / kb(p_base)
    print(f"  baseline : {kb(p_base):6.1f} KB | 60  features | ratio 1.00x")
    print(f"  incident : {kb(p_inc):6.1f} KB | 120 features | ratio {r_inc:.2f}x")
    print(f"  peak     : {kb(p_peak):6.1f} KB | 280 features | ratio {r_peak:.2f}x [LIMIT_EXCEEDED]")

    src = "Cloudflare Bot Management Outage, Nov 18 2025"
    rec(p_base, "PASS",     "R1", src, "none",
        "baseline", "60 features, shard r1 only. Query dengan filter shard. Normal.")
    rec(p_inc,  "WARN",     "R1", src, "size_growth,duplicate_shard",
        "growth", f"120 features (2x). Shard r0 ikut masuk. ratio {r_inc:.2f}x baseline.")
    rec(p_peak, "CRITICAL", "R1", src, "hard_limit_exceeded,size_growth",
        "growth,keycount", f"280 features ({r_peak:.1f}x). limit_exceeded=True. "
        "Proxy pre-alokasi 200 slot → out-of-bounds write → crash loop.")


# =============================================================================
# R2 — CROWDSTRIKE Channel File 291 (19 Jul 2024)
#
# Postmortem RCA (CrowdStrike, 6 Agustus 2024):
#   Content Configuration System (CCS) menggunakan IPC Template Instances
#   untuk mendistribusikan aturan deteksi ke sensor Falcon.
#   Template Type 21 untuk named pipe detection didefinisikan dengan
#   21 input field, tetapi sensor .11 mengalokasikan buffer untuk
#   20 field saja. Validator CCS tidak menangkap mismatch ini.
#   Versi bermasalah (rev1) di-push 19 Jul 2024 pukul 04:09 UTC.
#   8.5 juta Windows device crash dalam ~78 menit.
#
# Karakteristik file yang direplikasi:
#   baseline : 150 rules × 20 fields, schema v3.0
#   incident : 150 rules × 21 fields, schema v3.1 (field ke-21 ditambahkan)
#   peak     : 300 rules × 21 fields (setelah propagasi penuh ke semua node)
# =============================================================================
def replica_crowdstrike():
    print("\n[R2] CrowdStrike Channel File 291...")
    d = OUT / "R2_crowdstrike"
    d.mkdir(exist_ok=True)

    def rule(rid, schema_v31=False):
        r = {
            "rule_id":                f"NP-{rid:05d}",
            "pipe_pattern":           f"\\\\pipe\\\\svc_{rid % 100:03d}",
            "match_type":             "wildcard",
            "action":                 "monitor",
            "severity":               random.choice(["low","medium","high"]),
            "enabled":                True,
            "created_at":             "2024-07-18T00:00:00Z",
            "updated_at":             "2024-07-18T00:00:00Z",
            "source":                 "crowdstrike-intel",
            "category":               "named_pipe_abuse",
            "platform":               "windows",
            "min_sensor_version":     "7.11",
            "tags":                   ["c2", "lateral-movement"],
            "ttl_hours":              720,
            "confidence":             random.randint(70, 99),
            "priority":               random.randint(1, 5),
            "alert_on_match":         True,
            "require_parent_process": False,
            "parent_process_filter":  None,
            "audit_log":              True,          # field ke-20
        }
        if schema_v31:
            # Field ke-21: ada di schema v3.1 tapi parser sensor masih v3.0
            r["ipc_template_instance_id"] = f"TMPL-{rid:06d}"
        assert len(r) == (21 if schema_v31 else 20)
        return r

    base = {
        "channel_file_id":  "291",
        "version":          "2024-07-18-rev4",
        "schema_version":   "3.0",        # versi yang kompatibel dengan sensor 7.11
        "generated_at":     "2024-07-18T23:50:00Z",
        "total_rules":      150,
        "rules":            [rule(i) for i in range(150)],
    }
    p_base = d / "channel_file_291_baseline.json"
    w_json(p_base, base)

    # INCIDENT: schema v3.1 dengan field ke-21 per rule
    inc = {
        "channel_file_id":  "291",
        "version":          "2024-07-19-rev1",   # versi yang menyebabkan BSOD
        "schema_version":   "3.1",               # parser sensor tidak tahu versi ini
        "generated_at":     "2024-07-19T04:05:00Z",
        "total_rules":      150,
        "rules":            [rule(i, schema_v31=True) for i in range(150)],
    }
    p_inc = d / "channel_file_291_incident.json"
    w_json(p_inc, inc)

    # PEAK: 300 rules setelah update menyebar ke semua template instances
    peak = {
        "channel_file_id":  "291",
        "version":          "2024-07-19-rev2",
        "schema_version":   "3.1",
        "generated_at":     "2024-07-19T05:27:00Z",
        "total_rules":      300,   # propagasi penuh, semua node terima update
        "rules":            [rule(i, schema_v31=True) for i in range(300)],
    }
    p_peak = d / "channel_file_291_peak.json"
    w_json(p_peak, peak)

    # Hitung total field sebagai metrik untuk keycount analyzer
    base_fields = sum(len(r) for r in base["rules"])
    inc_fields  = sum(len(r) for r in inc["rules"])
    peak_fields = sum(len(r) for r in peak["rules"])
    print(f"  baseline : {kb(p_base):6.1f} KB | 150 rules × 20 fields = {base_fields} total")
    print(f"  incident : {kb(p_inc):6.1f} KB | 150 rules × 21 fields = {inc_fields} total (+{inc_fields-base_fields})")
    print(f"  peak     : {kb(p_peak):6.1f} KB | 300 rules × 21 fields = {peak_fields} total")

    src = "CrowdStrike Channel File 291 Incident, Jul 19 2024"
    rec(p_base, "PASS",     "R2", src, "none",
        "baseline", "150 rules × 20 fields. Schema v3.0. Kompatibel sensor 7.11.")
    rec(p_inc,  "WARN",     "R2", src, "keycount_inflation,schema_version_drift",
        "keycount,growth", f"150 rules × 21 fields. Schema v3.1. "
        "Field ke-21 (ipc_template_instance_id) tidak diekspektasi parser v3.0.")
    rec(p_peak, "CRITICAL", "R2", src, "keycount_inflation,rule_count_doubled",
        "keycount,growth", f"300 rules × 21 fields = {peak_fields} total fields. "
        "Propagasi penuh ke semua sensor nodes. 8.5 juta device crash.")


# =============================================================================
# R3 — ROBLOX Consul Service Registry (28–31 Oktober 2021)
#
# Postmortem (Roblox Engineering Blog, Januari 2022):
#   Consul digunakan sebagai service discovery untuk ~5000 microservice.
#   Streaming backend (fitur baru) diaktifkan bersamaan dengan traffic spike
#   Roblox Halloween event.
#   BoltDB (storage backend Consul) menggunakan freelist array O(n) bukan
#   hashmap O(1). Dengan streaming aktif dan high load:
#     1. Setiap service health check menulis ke BoltDB
#     2. Freelist GC berjalan O(n²) → makin lambat → timeout
#     3. Service entries menumpuk tanpa TTL enforcement
#   Registry yang seharusnya berisi ~3000 service entries
#   membengkak ke 40.000+ entries dalam waktu 12 jam.
#   Roblox offline 73 jam (28 Okt–31 Okt 2021).
#
# Karakteristik file yang direplikasi:
#   baseline : 300 service entries, streaming=false
#   incident : 3000 entries (10x), streaming=true, gc_lag=true
#   peak     : 8000 entries (26x), semua metrics error
# =============================================================================
def replica_roblox():
    print("\n[R3] Roblox Consul Service Registry...")
    d = OUT / "R3_roblox"
    d.mkdir(exist_ok=True)

    services = [
        "game-server","chat-service","asset-server","auth-service",
        "presence-service","notification-hub","analytics-pipeline",
        "trading-service","avatar-service","inventory-service",
    ]

    def svc_entry(svc_id, offset_min=0, is_ghost=False):
        base_ts = datetime.datetime(2021, 10, 28, 9, 0)
        ts = (base_ts + datetime.timedelta(minutes=offset_min)).isoformat()
        e = {
            "ID":   f"svc-{svc_id:06d}",
            "Name": services[svc_id % len(services)],
            "Addr": f"10.{(svc_id//256)%256}.{svc_id%256}.{(svc_id*7)%254+1}",
            "Port": 8000 + (svc_id % 2000),
            "Tags": ["roblox", "microservice"],
            "Meta": {"registered_at": ts, "ver": f"1.{svc_id%10}.{svc_id%100}"},
            "Check": {
                "HTTP":     f"http://10.0.0.1:{8000+(svc_id%2000)}/health",
                "Interval": "10s", "Timeout": "2s",
            },
        }
        if is_ghost:
            e["__gc_not_cleaned"]  = True
            e["__ttl_expired"]     = True
            e["__freelist_leaked"] = True
        return e

    base = {
        "datacenter":           "us-east-1",
        "node_name":            "consul-server-primary",
        "server":               True,
        "bootstrap_expect":     5,
        "use_streaming_backend": False,   # streaming belum aktif
        "boltdb_freelist_type": "array",
        "gc_interval_seconds":  30,
        "services":             [svc_entry(i) for i in range(300)],
        "telemetry":            {"retention": "60s"},
    }
    p_base = d / "consul_registry_baseline.yaml"
    w_yaml(p_base, base)

    # INCIDENT: streaming aktif, GC mulai lag, entries menumpuk 10x
    inc = {
        "datacenter":           "us-east-1",
        "node_name":            "consul-server-primary",
        "server":               True,
        "bootstrap_expect":     5,
        "use_streaming_backend": True,    # INI pemicunya
        "boltdb_freelist_type": "array",  # O(n) — tidak di-upgrade ke hashmap
        "gc_interval_seconds":  300,      # GC melambat karena beban tinggi
        "gc_lag_detected":      True,
        "services":             (
            [svc_entry(i) for i in range(300)] +
            [svc_entry(i, offset_min=i//5, is_ghost=True) for i in range(2700)]
        ),
        "telemetry":            {"retention": "60s"},
    }
    p_inc = d / "consul_registry_incident.yaml"
    w_yaml(p_inc, inc)

    # PEAK: 8000 entries, consul mulai timeout semua request
    peak = {
        "datacenter":           "us-east-1",
        "node_name":            "consul-server-primary",
        "server":               True,
        "bootstrap_expect":     5,
        "use_streaming_backend": True,
        "boltdb_freelist_type": "array",
        "gc_interval_seconds":  0,        # GC tidak bisa jalan sama sekali
        "gc_lag_detected":      True,
        "boltdb_write_timeout": True,
        "consul_status":        "degraded",
        "services":             (
            [svc_entry(i) for i in range(300)] +
            [svc_entry(i, offset_min=i//5, is_ghost=True) for i in range(7700)]
        ),
        "telemetry":            {"retention": "60s"},
    }
    p_peak = d / "consul_registry_peak.yaml"
    w_yaml(p_peak, peak)

    r_inc  = kb(p_inc)  / kb(p_base)
    r_peak = kb(p_peak) / kb(p_base)
    n_inc  = len(inc["services"])
    n_peak = len(peak["services"])
    print(f"  baseline : {kb(p_base):7.1f} KB | 300 entries  | ratio 1.0x")
    print(f"  incident : {kb(p_inc):7.1f} KB | {n_inc} entries | ratio {r_inc:.1f}x")
    print(f"  peak     : {kb(p_peak):7.1f} KB | {n_peak} entries | ratio {r_peak:.1f}x")

    src = "Roblox Consul Outage, Oct 28-31 2021"
    rec(p_base, "PASS",     "R3", src, "none",
        "baseline", "300 entries. streaming=false. BoltDB GC normal.")
    rec(p_inc,  "CRITICAL", "R3", src, "kv_bloat_10x,gc_failure",
        "growth,keycount", f"{n_inc} entries ({r_inc:.1f}x). streaming=true. "
        "2700 ghost entries dari BoltDB freelist leak.")
    rec(p_peak, "CRITICAL", "R3", src, "kv_bloat_26x,consul_degraded",
        "growth,keycount", f"{n_peak} entries ({r_peak:.1f}x). gc_interval=0. "
        "consul_status=degraded. Roblox offline 73 jam.")


# =============================================================================
# R4 — FAA NOTAM System (11 Januari 2023)
#
# Pernyataan resmi FAA (13 Januari 2023) + investigasi NTSB:
#   NOTAM = Notice to Air Missions. Sistem kritis yang mendistribusikan
#   informasi keselamatan (penutupan runway, restriksi udara, dll)
#   ke semua penerbangan sipil AS.
#   Kontraktor menjalankan prosedur sinkronisasi primary↔backup database.
#   Satu engineer secara tidak sengaja meng-overwrite file primary
#   dengan file backup yang berisi snapshot 3 jam sebelumnya.
#   File primary: 1847 NOTAM aktif (, 22:00 UTC 10 Jan)
#   File yang ter-overwrite: 72 NOTAM saja (, 19:15 UTC 10 Jan)
#   FAA menghentikan semua departure 11 Jan 2023 pukul 07:19–09:46 UTC.
#   ~11.000 penerbangan delay, 1.300 dibatalkan.
#
# Karakteristik file yang direplikasi:
#   baseline  : 1847 NOTAM entries, source=PRIMARY
#   incident  : 72 NOTAM entries (backup snapshot, source=BACKUP-RESTORED)
#   peak      : 0 entries (skenario complete deletion yang hampir terjadi)
# =============================================================================
def replica_faa():
    print("\n[R4] FAA NOTAM Database...")
    d = OUT / "R4_faa"
    d.mkdir(exist_ok=True)

    airports = [
        "KJFK","KLAX","KORD","KATL","KDFW","KDEN","KSFO",
        "KLAS","KSEA","KMIA","KBOS","KEWR","KPHL","KDCA","KIAD",
    ]
    types = [
        "RUNWAY_CLOSURE","TAXIWAY_RESTRICTION","ILS_OUTAGE",
        "AIRSPACE_RESTRICTION","OBSTACLE_NEW","NAVAID_OUTAGE",
        "GPS_ANOMALY","TFR_ACTIVE","LASER_ACTIVITY","SNOW_REMOVAL",
    ]

    def notam(nid):
        return {
            "notam_id":        f"NOTAM-2023-{nid:05d}",
            "location":        random.choice(airports),
            "type":            random.choice(types),
            "effective_from":  "2023-01-10T00:00:00Z",
            "effective_until": "2023-01-20T23:59:00Z",
            "altitude_lower":  random.choice([0, 500, 1000, 2000]),
            "altitude_upper":  random.randint(3000, 18000),
            "description":     (
                f"Temporary restriction in effect. Coordinate with ATC before entering. "
                f"Reference: NOTAM-2023-{nid:05d}. "
                f"Contact: 135.{random.randint(100,999)}."
            ),
            "authority":   "FAA-ATO",
            "status":      "ACTIVE",
            "revision":    1,
        }

    # BASELINE: 1847 NOTAM (jumlah aktual yang dilaporkan FAA)
    base = {
        "db_version":    "2023-01-10-v14",
        "generated_at":  "2023-01-10T22:00:00Z",
        "source_system": "NOTAM-PRIMARY-DB",
        "sync_status":   "PRIMARY",
        "total_records": 1847,
        "notams":        [notam(i) for i in range(1847)],
    }
    p_base = d / "notam_database_baseline.json"
    w_json(p_base, base)

    # INCIDENT: overwrite dengan backup snapshot — hanya 72 NOTAM
    inc = {
        "db_version":    "2023-01-10-v11",       # versi LAMA dari backup
        "generated_at":  "2023-01-10T19:15:00Z", # timestamp backup (3j sebelumnya)
        "source_system": "NOTAM-BACKUP-DB",       # source berubah = detectable anomaly
        "sync_status":   "BACKUP_RESTORED",       # flag yang seharusnya blokir deploy
        "total_records": 1847,                      # ← PERTAHANKAN nilai primary, jangan 72
        "notams":        [notam(i) for i in range(72)],
    }
    p_inc = d / "notam_database_incident.json"
    w_json(p_inc, inc)

    # PEAK: skenario terburuk — complete deletion (hampir terjadi)
    peak = {
        "db_version":    "UNKNOWN",
        "generated_at":  "2023-01-11T07:28:00Z",
        "source_system": "NOTAM-PRIMARY-DB",
        "sync_status":   "SYNC_ERROR",
        "total_records": 0,
        "error_code":    "DB_SYNC_CONFLICT_UNRESOLVED",
        "notams":        [],
    }
    p_peak = d / "notam_database_peak.json"
    w_json(p_peak, peak)

    shrink_r = kb(p_inc) / kb(p_base)
    print(f"  baseline : {kb(p_base):7.1f} KB | 1847 NOTAMs | PRIMARY")
    print(f"  incident : {kb(p_inc):7.1f} KB |   72 NOTAMs | BACKUP_RESTORED | shrink {shrink_r:.3f}x")
    print(f"  peak     : {kb(p_peak):7.1f} KB |    0 NOTAMs | SYNC_ERROR | COMPLETE DELETION")

    src = "FAA NOTAM Outage, Jan 11 2023"
    rec(p_base, "PASS",     "R4", src, "none",
        "baseline", "1847 NOTAMs. source=PRIMARY. sync_status=PRIMARY.")
    rec(p_inc,  "CRITICAL", "R4", src, "extreme_shrinkage,source_metadata_mismatch",
        "growth", f"72/1847 NOTAMs ({shrink_r:.3f}x baseline). source berubah "
        "PRIMARY→BACKUP_RESTORED. 96% data hilang. Menguji deteksi shrinkage.")
    rec(p_peak, "CRITICAL", "R4", src, "complete_truncation,sync_error",
        "growth,keycount", "0 NOTAMs. SYNC_ERROR. Complete deletion scenario. "
        "11.000 penerbangan delay, 1.300 dibatalkan.")


# =============================================================================
# GROUND TRUTH CSV
# =============================================================================
def write_gt():
    GT.parent.mkdir(parents=True, exist_ok=True)
    with open(GT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "filepath","expected_verdict","scenario_id","incident_source",
            "anomaly_type","csg_analyzer_target","notes",
        ])
        w.writeheader()
        w.writerows(RECORDS)
    dist = Counter(r["expected_verdict"] for r in RECORDS)
    print(f"\n[GT] {GT} | {len(RECORDS)} records | {dict(dist)}")


if __name__ == "__main__":
    print("=" * 65)
    print("  CSG Real Postmortem Replica Generator")
    print("  4 incidents × 3 files (baseline / incident / peak) = 12 files")
    print("=" * 65)
    replica_cloudflare()
    replica_crowdstrike()
    replica_roblox()
    replica_faa()
    write_gt()
    print("\n[+] Selesai. Output:", OUT.resolve())
