"""
CSG Incident Scenario Generator — Injection-Based, Format-Agnostic
===================================================================
Membaca SEMUA 50 file dari 1_benign_standard tanpa melewatkan satu pun,
lalu menyuntikkan anomali sesuai 4 skenario insiden nyata.

Arsitektur kunci:
  - FORMAT-AGNOSTIC  : mendukung JSON, YAML, TOML, INI, .conf, .env,
                       .properties, dan teks apapun via text-mode injector
  - ZERO-SKIP        : setiap file yang berhasil dibaca PASTI diproses,
                       gagal parse bukan alasan skip — fallback ke text-mode
  - CLEAN PARTITION  : 50 file dibagi ke 4 skenario (10-13 per skenario)
                       dengan slicing langsung [start:end], tanpa modulo

Skenario (masing-masing ~10 file):
  [S1] Cloudflare  Nov 2025 — size doubling via duplicate section
  [S2] CrowdStrike Jul 2024 — extra field per item in list-of-dicts
  [S3] Roblox      Okt 2021 — list/content 10x bloat
  [S4] FAA NOTAM   Jan 2023 — extreme shrinkage (~3% of original)

Cara menjalankan:
  python generate_incident_scenarios.py
  python generate_incident_scenarios.py --benign-dir PATH/TO/1_benign_standard

Output:
  tests/evaluation_dataset/2_config_drift_simulated/<sid>_*/
  tests/evaluation_dataset/ground_truth_drift_scenarios.csv
"""

import json
import re
import csv
import copy
import math
import random
import hashlib
import argparse
import sys
from pathlib import Path
from collections import Counter
from typing import Any

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import tomllib          # Python 3.11+
    HAS_TOML = True
except ImportError:
    try:
        import tomli as tomllib  # pip install tomli
        HAS_TOML = True
    except ImportError:
        HAS_TOML = False

random.seed(42)

FILES_PER_SCENARIO = 10
SCENARIOS          = 4
TOTAL_FILES        = FILES_PER_SCENARIO * SCENARIOS   # 40

BASE_OUTPUT = Path("tests/evaluation_dataset/2_config_drift_simulated")
GT_PATH     = Path("tests/evaluation_dataset/ground_truth_drift_scenarios.csv")

GROUND_TRUTH: list[dict] = []


# =============================================================================
# LAYER 1 — FORMAT-AGNOSTIC READER
# Setiap file pasti menghasilkan (data, fmt).
# fmt adalah "json" | "yaml" | "text"  — tidak pernah gagal total.
# =============================================================================

def _try_json(text: str):
    return json.loads(text)

def _try_yaml(text: str):
    if not HAS_YAML:
        raise ImportError("pyyaml not installed")
    result = yaml.safe_load(text)
    if result is None:
        raise ValueError("YAML parsed to None")
    return result

def _try_toml(path: Path):
    if not HAS_TOML:
        raise ImportError("tomllib/tomli not available")
    with open(path, "rb") as f:
        return tomllib.load(f)

def _parse_ini_env_properties(text: str) -> dict:
    """
    Parser ringan untuk INI, .env, .properties, .conf key=value.
    Menghasilkan dict flat {section.key: value} atau {key: value}.
    """
    result = {}
    current_section = ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        # Deteksi header section [section]
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip() + "."
            continue
        # Deteksi key = value atau key : value
        for sep in ("=", ":"):
            if sep in line:
                k, _, v = line.partition(sep)
                full_key = current_section + k.strip()
                result[full_key] = v.strip()
                break
    return result if result else None


def load_file(path: Path) -> tuple[Any, str]:
    """
    Baca file dan kembalikan (data, fmt).
    fmt = "json" | "yaml" | "text"
    Data TIDAK PERNAH None — text-mode fallback menjamin ini.
    """
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        # Bahkan read() gagal pun, kembalikan string kosong
        return f"[unreadable: {e}]", "text"

    suffix = path.suffix.lower()

    # ── Coba JSON ────────────────────────────────────────────────────────────
    if suffix == ".json":
        try:
            return _try_json(raw), "json"
        except Exception:
            pass  # rusak tapi tetap lanjut ke fallback

    # ── Coba YAML / YML ──────────────────────────────────────────────────────
    if suffix in (".yaml", ".yml"):
        try:
            return _try_yaml(raw), "yaml"
        except Exception:
            pass

    # ── Coba TOML ────────────────────────────────────────────────────────────
    if suffix == ".toml":
        try:
            return _try_toml(path), "yaml"   # tulis ulang sebagai YAML
        except Exception:
            # TOML tidak bisa di-parse → fallback ke INI parser atau text
            parsed = _parse_ini_env_properties(raw)
            if parsed:
                return parsed, "yaml"

    # ── Coba INI / .env / .conf / .properties ────────────────────────────────
    if suffix in (".ini", ".cfg", ".conf", ".env", ".properties"):
        parsed = _parse_ini_env_properties(raw)
        if parsed:
            return parsed, "yaml"   # simpan sebagai YAML supaya injector bisa baca

    # ── Universal text fallback — TIDAK PERNAH SKIP ──────────────────────────
    # File apapun yang tidak bisa di-parse tetap masuk sebagai string mentah.
    # Injector punya cabang text-mode untuk menangani ini.
    return raw, "text"


def save_file(data: Any, fmt: str, path: Path) -> None:
    """Tulis hasil injeksi. fmt = 'json' | 'yaml' | 'text'."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        try:
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                            encoding="utf-8")
            return
        except Exception:
            fmt = "text"   # fallback

    if fmt == "yaml" and HAS_YAML:
        try:
            path.write_text(
                yaml.dump(data, default_flow_style=False,
                          allow_unicode=True, sort_keys=False),
                encoding="utf-8"
            )
            return
        except Exception:
            fmt = "text"   # fallback

    # text-mode: konversi ke string kalau belum
    if not isinstance(data, str):
        try:
            data = json.dumps(data, indent=2, ensure_ascii=False)
        except Exception:
            data = str(data)
    path.write_text(data, encoding="utf-8")


def file_size_kb(path: Path) -> float:
    return path.stat().st_size / 1024


# =============================================================================
# LAYER 2 — STRUKTUR NAVIGATOR (untuk structured mode)
# =============================================================================

def find_largest_list(data: Any) -> tuple[list, list] | None:
    """Cari list terbesar secara rekursif, kembalikan (list_ref, path)."""
    def _walk(node, path):
        best = None
        if isinstance(node, list) and len(node) > 1:
            best = (node, path)
        if isinstance(node, dict):
            for k, v in node.items():
                c = _walk(v, path + [k])
                if c and (best is None or len(c[0]) > len(best[0])):
                    best = c
        elif isinstance(node, list):
            for i, item in enumerate(node):
                c = _walk(item, path + [i])
                if c and (best is None or len(c[0]) > len(best[0])):
                    best = c
        return best
    return _walk(data, [])


def find_dict_lists(data: Any) -> list[tuple[list, list]]:
    """Cari semua list yang isinya dict, kembalikan [(list_ref, path)]."""
    results = []
    def _walk(node, path):
        if isinstance(node, list):
            if node and all(isinstance(i, dict) for i in node):
                results.append((node, path))
        if isinstance(node, dict):
            for k, v in node.items():
                _walk(v, path + [k])
        elif isinstance(node, list):
            for i, item in enumerate(node):
                _walk(item, path + [i])
    _walk(data, [])
    return results


def find_integers(data: Any) -> list[tuple[Any, str | int]]:
    """Cari semua (parent_container, key) yang nilainya integer."""
    results = []
    def _walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, int) and not isinstance(v, bool):
                    results.append((node, k))
                else:
                    _walk(v)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                if isinstance(item, int) and not isinstance(item, bool):
                    results.append((node, i))
                else:
                    _walk(item)
    _walk(data)
    return results


def set_nested(data: Any, path: list, value: Any) -> None:
    for key in path[:-1]:
        data = data[key]
    data[path[-1]] = value


def get_nested(data: Any, path: list) -> Any:
    for key in path:
        data = data[key]
    return data


# =============================================================================
# LAYER 3 — INJECTORS
# Setiap injector memiliki dua cabang:
#   - structured : data adalah dict/list  → manipulasi data structure
#   - text       : data adalah str        → manipulasi string mentah
# Kembalikan (mutated_data, fmt_out, detail_string)
# =============================================================================

def inject_s1_cloudflare(data: Any, fmt: str) -> tuple[Any, str, str]:
    """
    Cloudflare Nov 2025: size doubling via duplicate entries.
    ClickHouse mengembalikan baris duplikat dari shard r0 karena
    DB permission change — feature file membengkak 2x.
    """
    if fmt == "text":
        # TEXT MODE: duplikasi seluruh konten dengan marker shard
        doubled = data + "\n# --- SHARD_R0_DUPLICATE ---\n" + data
        return doubled, "text", f"text content doubled ({len(data)} -> {len(doubled)} chars)"

    # STRUCTURED MODE
    data = copy.deepcopy(data)
    result = find_largest_list(data)

    if result:
        original_list, path = result
        dupes = []
        for item in original_list:
            dup = copy.deepcopy(item)
            if isinstance(dup, dict):
                dup["__shard_origin"] = "r0_duplicate"
            dupes.append(dup)
        new_list = original_list + dupes
        if path:
            set_nested(data, path, new_list)
        else:
            data = new_list
        detail = (f"list at '{'.'.join(str(p) for p in path) or 'root'}' "
                  f"doubled: {len(original_list)} -> {len(new_list)} entries")
    else:
        # Tidak ada list — duplikasi seluruh root dict
        if isinstance(data, dict):
            data["__shard_r0_duplicate"] = copy.deepcopy(data)
        detail = "root dict duplicated as shard injection"

    return data, fmt, detail


def inject_s2_crowdstrike(data: Any, fmt: str) -> tuple[Any, str, str]:
    """
    CrowdStrike Jul 2024: extra field per dict item.
    Channel File 291 punya field ke-21 yang tidak diekspektasi
    parser sensor → out-of-bounds read → BSOD massal.
    """
    if fmt == "text":
        # TEXT MODE: sisipkan field extra di setiap baris key=value
        lines = data.splitlines()
        new_lines = []
        injected = 0
        for line in lines:
            new_lines.append(line)
            if "=" in line or ":" in line:
                new_lines.append("field_n_plus_1_unexpected=injected_by_content_system_bug")
                injected += 1
        return "\n".join(new_lines), "text", f"extra field injected after {injected} lines"

    # STRUCTURED MODE
    data = copy.deepcopy(data)
    candidates = find_dict_lists(data)
    injected = 0

    if candidates:
        target_list, path = max(candidates, key=lambda x: len(x[0]))
        for item in target_list:
            item["__field_n_plus_1_unexpected"] = "injected_by_content_system_bug"
            injected += 1
        if path:
            set_nested(data, path, target_list)
        detail = f"extra field injected into {injected} dict items in list"
    elif isinstance(data, dict):
        data["__field_n_plus_1_unexpected"] = "injected_by_content_system_bug"
        injected = 1
        detail = "extra field injected into root dict (no list-of-dicts found)"
    else:
        detail = "no injection point found (noop)"

    return data, fmt, detail


def inject_s3_roblox(data: Any, fmt: str) -> tuple[Any, str, str]:
    """
    Roblox Okt 2021: 10x list bloat.
    Consul service registry menumpuk karena BoltDB freelist GC failure
    saat streaming diaktifkan di bawah beban tinggi.
    """
    if fmt == "text":
        # TEXT MODE: ulangi konten 10x
        bloated = ""
        for copy_num in range(10):
            bloated += f"# --- COPY_{copy_num} (gc_not_cleaned=true) ---\n"
            bloated += data + "\n"
        return bloated, "text", f"text content repeated 10x ({len(data)} -> {len(bloated)} chars)"

    # STRUCTURED MODE
    data = copy.deepcopy(data)
    result = find_largest_list(data)

    if result:
        original_list, path = result
        original_len = len(original_list)
        bloated = list(original_list)
        for copy_num in range(1, 10):
            for item in original_list:
                dup = copy.deepcopy(item)
                if isinstance(dup, dict):
                    dup["__ghost_copy"]    = copy_num
                    dup["__gc_not_cleaned"] = True
                bloated.append(dup)
        if path:
            set_nested(data, path, bloated)
        else:
            data = bloated
        detail = (f"list bloated 10x: {original_len} -> {len(bloated)} entries")
    elif isinstance(data, dict):
        data["__accumulated_ghost_entries"] = [
            {"entry_id": i, "status": "ghost", "gc_not_cleaned": True}
            for i in range(300)
        ]
        detail = "300 ghost entries injected (no list found)"
    else:
        detail = "no injection point"

    return data, fmt, detail


def inject_s4_faa(data: Any, fmt: str) -> tuple[Any, str, str]:
    """
    FAA NOTAM Jan 2023: extreme shrinkage (~3% of original).
    Engineer salah replace primary DB dengan backup snapshot lama
    → file primary menyusut drastis → seluruh penerbangan AS terhenti.
    Ini menguji deteksi anomali NEGATIF (shrinkage) oleh growth analyzer.
    """
    # Serialisasi ke string dulu untuk hitung ukuran asli secara konsisten
    if fmt == "text":
        original_str = data
    else:
        try:
            original_str = json.dumps(data, indent=2, ensure_ascii=False)
        except Exception:
            original_str = str(data)

    original_size = len(original_str)
    # Buat stub minimal yang PASTI lebih kecil (bukan 3% dari konten asli,
    # melainkan stub backup metadata + 1 item pertama saja)
    # Stub yang SELALU lebih kecil: hanya 3 key pendek, nilai literal
    # sehingga shrinkage dijamin bahkan untuk file asli yang sudah kecil.
    # Jika file asli < 80 chars, kita paksa stub ke string 1 baris saja.
    STUB_JSON = '{"__src":"BAK","__status":"PARTIAL","__ver":"snap-3h"}'
    stub_size = len(STUB_JSON)

    if fmt == "text":
        if original_size <= stub_size:
            # File asli sudah lebih kecil dari stub — potong lebih agresif
            out = original_str[:max(10, original_size // 5)]
        else:
            out = STUB_JSON
        ratio = len(out) / original_size if original_size else 0
        return (out, "text",
                f"truncated to {ratio:.1%} ({original_size}->{len(out)} chars). SHRINKAGE")

    # structured mode — kembalikan dict minimal
    stub = {"__src": "BAK", "__status": "PARTIAL", "__ver": "snap-3h"}
    new_size = stub_size
    ratio    = new_size / original_size if original_size else 0
    return (stub, "yaml",
            f"truncated to {ratio:.1%} ({original_size}->{new_size} chars). "
            "Minimal backup stub. SHRINKAGE anomaly.")


# =============================================================================
# LAYER 4 — SCENARIO REGISTRY
# =============================================================================

SCENARIO_META: dict[str, dict] = {
    "S1": {
        "name":     "Cloudflare Bot Feature File Doubled",
        "date":     "Nov 18 2025",
        "source":   "Cloudflare Bot Management Outage, Nov 18 2025",
        "anomaly":  "size_doubling,duplicate_shard_entries",
        "analyzer": "growth",
        "verdict":  "CRITICAL",
        "injector": inject_s1_cloudflare,
        "subdir":   "S1_cloudflare_feature_file_doubled",
    },
    "S2": {
        "name":     "CrowdStrike Channel File 291 Field Inflation",
        "date":     "Jul 19 2024",
        "source":   "CrowdStrike Channel File 291 RCA, Jul 19 2024",
        "anomaly":  "keycount_inflation,extra_field_per_item",
        "analyzer": "keycount,growth",
        "verdict":  "WARN",
        "injector": inject_s2_crowdstrike,
        "subdir":   "S2_crowdstrike_field_count_anomaly",
    },
    "S3": {
        "name":     "Roblox Consul KV Bloat 10x",
        "date":     "Oct 28 2021",
        "source":   "Roblox Consul Outage, Oct 28-31 2021",
        "anomaly":  "list_bloat_10x,gc_failure_simulation",
        "analyzer": "growth,keycount",
        "verdict":  "CRITICAL",
        "injector": inject_s3_roblox,
        "subdir":   "S3_roblox_consul_kv_bloat",
    },
    "S4": {
        "name":     "FAA NOTAM File Truncation",
        "date":     "Jan 11 2023",
        "source":   "FAA NOTAM Outage, Jan 11 2023",
        "anomaly":  "extreme_shrinkage,backup_metadata_mismatch",
        "analyzer": "growth",
        "verdict":  "CRITICAL",
        "injector": inject_s4_faa,
        "subdir":   "S4_faa_file_truncation_anomaly",
    },
}


# =============================================================================
# LAYER 5 — PARTITIONER (FIXED: slicing langsung, tanpa modulo)
# =============================================================================

def partition_files(files: list[Path]) -> dict[str, list[Path]]:
    """
    Bagi files ke 4 skenario, masing-masing FILES_PER_SCENARIO file.
    Menggunakan slicing langsung [start:end] — BUKAN modulo — untuk
    memastikan setiap file masuk tepat SATU skenario tanpa duplikasi.

    Jika jumlah file < 40: pad dengan siklus (cycle) agar kuota terpenuhi.
    Jika jumlah file > 40: semua file tetap diproses, sisa dibagi rata.
    """
    sids   = list(SCENARIO_META.keys())
    pool   = files.copy()
    random.shuffle(pool)

    if len(pool) < TOTAL_FILES:
        # Pad dengan siklus: file_0, file_1, ... berulang hingga cukup
        cycled = []
        idx = 0
        while len(cycled) < TOTAL_FILES:
            cycled.append(pool[idx % len(pool)])
            idx += 1
        pool = cycled
        print(f"  [i] {len(files)} file di-pad ke {TOTAL_FILES} dengan siklus.")
    elif len(pool) > TOTAL_FILES:
        # Lebih dari 40: bagi merata, sisa masuk ke skenario terakhir
        extra = len(pool) - TOTAL_FILES
        print(f"  [i] {len(pool)} file tersedia. {extra} file ekstra dibagi ke skenario terakhir.")

    assignment: dict[str, list[Path]] = {}

    if len(pool) == TOTAL_FILES:
        # Kasus sempurna: tepat 50 file → partition bersih
        for i, sid in enumerate(sids):
            start = i * FILES_PER_SCENARIO           # 0, 10, 20, 30, 40
            end   = start + FILES_PER_SCENARIO        # 10, 20, 30, 40, 50
            assignment[sid] = pool[start:end]         # slice eksklusif, TANPA modulo
    else:
        # Lebih dari 50: bagi seadil mungkin
        base, extra = divmod(len(pool), len(sids))
        idx = 0
        for i, sid in enumerate(sids):
            size = base + (1 if i < extra else 0)
            assignment[sid] = pool[idx: idx + size]
            idx += size

    return assignment


# =============================================================================
# LAYER 6 — PIPELINE UTAMA
# =============================================================================

def collect_all_files(benign_dir: Path) -> list[Path]:
    """
    Kumpulkan SEMUA file dari direktori (rekursif satu level).
    Tidak ada filter ekstensi — format apapun diterima.
    """
    files = [f for f in sorted(benign_dir.iterdir()) if f.is_file()]
    print(f"  [i] Ditemukan {len(files)} file di {benign_dir}")
    return files


def run_pipeline(benign_dir: Path) -> None:
    BASE_OUTPUT.mkdir(parents=True, exist_ok=True)

    # 1. Kumpulkan semua file (tanpa filter)
    all_files = collect_all_files(benign_dir)
    if not all_files:
        print("[ERROR] Direktori kosong.")
        sys.exit(1)

    # 2. Partisi ke 5 skenario
    assignment = partition_files(all_files)

    # 3. Verifikasi partisi (tidak ada file yang overlap antar skenario)
    all_assigned = [f for files in assignment.values() for f in files]
    _verify_partition(assignment, all_files)

    # 4. Jalankan injeksi per skenario
    total_success = 0
    total_files   = sum(len(v) for v in assignment.values())

    for sid, meta in SCENARIO_META.items():
        subdir = BASE_OUTPUT / meta["subdir"]
        subdir.mkdir(exist_ok=True)
        files_for_sid = assignment[sid]

        print(f"\n[{sid}] {meta['name']} ({meta['date']})")
        print(f"      {len(files_for_sid)} file akan diinjeksi")
        print(f"      {'Asal file':<38} {'Sebelum':>8} {'Sesudah':>8}  Rasio")
        print(f"      {'-'*38} {'-'*8} {'-'*8}  {'-'*12}")

        sid_success = 0
        for origin in files_for_sid:
            # Baca — TIDAK pernah skip, text-mode sebagai fallback
            data, fmt = load_file(origin)

            # Injeksi
            try:
                mutated, fmt_out, detail = meta["injector"](data, fmt)
            except Exception as e:
                # Injector crash — fallback ke text inject manual
                raw_text = data if isinstance(data, str) else str(data)
                mutated  = raw_text + f"\n# INJECTION_ERROR: {e}\n# FALLBACK_MARKER: {sid}"
                fmt_out  = "text"
                detail   = f"injector exception: {e} — fallback text marker applied"

            # Simpan dengan nama: stem__sid.ext
            out_stem = f"{origin.stem}__{sid.lower()}"
            out_ext  = origin.suffix if origin.suffix else ".txt"
            out_path = subdir / f"{out_stem}{out_ext}"

            save_file(mutated, fmt_out, out_path)

            # Hitung rasio ukuran
            orig_kb = file_size_kb(origin)
            out_kb  = file_size_kb(out_path)
            ratio   = out_kb / orig_kb if orig_kb > 0 else 0
            tag     = "SHRINK" if ratio < 0.5 else f"{ratio:.1f}x"
            print(f"      {origin.name:<38} {orig_kb:>7.1f}K {out_kb:>7.1f}K  {tag}")

            # Catat ground truth — file anomali
            GROUND_TRUTH.append({
                "filepath":            str(out_path),
                "expected_verdict":    meta["verdict"],
                "scenario_id":         sid,
                "incident_source":     meta["source"],
                "anomaly_type":        meta["anomaly"],
                "csg_analyzer_target": meta["analyzer"],
                "inject_detail":       detail,
                "origin_file":         str(origin),
            })

            sid_success += 1
            total_success += 1

        print(f"      [{sid}] {sid_success}/{len(files_for_sid)} berhasil.")

    print(f"\n[+] Total: {total_success}/{total_files} file diinjeksi.")


def _verify_partition(assignment: dict, all_files: list[Path]) -> None:
    """Verifikasi tidak ada file yang terduplikasi di skenario berbeda."""
    path_to_sids: dict[Path, list[str]] = {}
    for sid, files in assignment.items():
        for f in files:
            path_to_sids.setdefault(f, []).append(sid)

    dupes = {p: sids for p, sids in path_to_sids.items() if len(sids) > 1}
    if dupes:
        print(f"  [!] PERINGATAN: {len(dupes)} file muncul di >1 skenario (karena pad/cycle):")
        for p, sids in list(dupes.items())[:3]:
            print(f"      {p.name} → {sids}")
    else:
        print(f"  [OK] Partisi bersih: tidak ada file yang overlap antar skenario.")

    # Distribusi per skenario
    dist = {sid: len(files) for sid, files in assignment.items()}
    print(f"  [OK] Distribusi: {dist}")


# =============================================================================
# LAYER 7 — GROUND TRUTH CSV
# =============================================================================

def write_ground_truth() -> None:
    GT_PATH.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "filepath", "expected_verdict", "scenario_id",
        "incident_source", "anomaly_type",
        "csg_analyzer_target", "inject_detail", "origin_file",
    ]
    with open(GT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(GROUND_TRUTH)

    dist = Counter(r["expected_verdict"] for r in GROUND_TRUTH)
    print(f"\n[GT] Ground truth -> {GT_PATH}")
    print(f"     {len(GROUND_TRUTH)} records | Distribusi: {dict(dist)}")


# =============================================================================
# LAYER 8 — RINGKASAN AKHIR
# =============================================================================

def print_summary() -> None:
    print("\n" + "=" * 68)
    print("  RINGKASAN EKSEKUSI")
    print("=" * 68)
    rows = [
        ("S1","Cloudflare Feature File",  "Nov 2025","growth (2x size)"),
        ("S2","CrowdStrike Channel File", "Jul 2024","keycount (field+1)"),
        ("S3","Roblox Consul KV Bloat",   "Okt 2021","growth+keycount (10x)"),
        ("S4","FAA NOTAM Truncation",     "Jan 2023","growth (shrinkage 3%)"),
    ]
    for sid, name, date, analyzer in rows:
        print(f"  [{sid}] {name} ({date}) -> {analyzer}")

    print("""
  FORMAT YANG DIDUKUNG (format-agnostic):
    JSON, YAML, YML, TOML, INI, CFG, CONF, ENV, PROPERTIES
    + fallback text-mode untuk format apapun lainnya

  NAMING CONVENTION OUTPUT:
    {stem}__{sid.lower()}{ext}
    Contoh: nginx_31.conf → nginx_31__s1.conf
    """)


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CSG Injection-Based Scenario Generator — Format Agnostic"
    )
    parser.add_argument(
        "--benign-dir",
        type=Path,
        default=Path("tests/evaluation_dataset/1_benign_standard"),
        help="Path ke direktori berisi file config bersih",
    )
    args = parser.parse_args()

    print("=" * 68)
    print("  CSG Incident Scenario Generator")
    print("  Format-Agnostic | Zero-Skip | Clean Partition")
    print("=" * 68)

    if not args.benign_dir.exists():
        print(f"[ERROR] Direktori tidak ditemukan: {args.benign_dir}")
        sys.exit(1)

    run_pipeline(args.benign_dir)
    write_ground_truth()
    print_summary()
    print("[+] Selesai.")