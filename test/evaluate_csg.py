"""
tests/evaluate_csg.py
Evaluasi CSG terhadap 3 kohort dataset (112 spesimen):

  1_benign_standard              (50) PASS           -> ukur False Positive
  2_config_drift_simulated       (50) WARN/CRITICAL  -> ukur TP & FN
  3_real_postmortem_replicas     (12) PASS/WARN/CRIT -> validasi insiden nyata
"""
import subprocess
import json
import csv
import re
from pathlib import Path

DATASET_ROOT = Path("tests/evaluation_dataset")
GT_FILES = [
    ("1_benign_standard (FP)", DATASET_ROOT / "ground_truth_benign.csv"),
    ("2_config_drift_simulated (TP/FN)", DATASET_ROOT / "ground_truth_drift_scenarios.csv"),
    ("3_real_postmortem_replicas", DATASET_ROOT / "ground_truth_postmortem_replicas.csv"),
]
SCAN_ROOT = "tests/growth_simulation_repo"
# Path absolut ke root proyek CSG (direktori tempat pyproject.toml berada)
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def setup_arena():
    print("[*] 1. Menyiapkan Arena Simulasi Git (benign + drift + postmortem)...")
    subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-File", "tests/setup_growth_test.ps1"],
        check=True,
        stdout=subprocess.DEVNULL,
        cwd=PROJECT_ROOT,
    )
    # Bangun baseline dari commit HEAD~1 (konfigurasi stabil) di dalam repo simulasi
    # agar Layer 1 (growth) punya angka pembanding yang valid.
    print("[*] 1b. Membangun baseline dari HEAD~1 repo simulasi...")
    sim_repo = PROJECT_ROOT / SCAN_ROOT
    _build_baseline_from_git_history(sim_repo)

def _build_baseline_from_git_history(sim_repo: Path) -> None:
    """
    Checkout HEAD~1 sementara, scan semua file, simpan ke .csg-baseline.json
    di dalam growth_simulation_repo, lalu kembali ke HEAD.
    Ini memastikan Layer 1 (growth analyzer) punya data pembanding yang benar.
    """
    import tempfile, shutil

    baseline_path = sim_repo / ".csg-baseline.json"

    # Kumpulkan daftar file yang ada di HEAD~1 via git ls-tree
    try:
        ls = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", "HEAD~1"],
            capture_output=True, text=True, check=True, cwd=sim_repo,
        )
    except subprocess.CalledProcessError:
        print("[!] Gagal membaca HEAD~1 — baseline tidak dibangun")
        return

    files_in_prev = [l.strip() for l in ls.stdout.splitlines() if l.strip()]

    # Ambil ukuran setiap file dari HEAD~1 via git cat-file -s
    baseline_files: dict = {}
    for rel_path in files_in_prev:
        try:
            r = subprocess.run(
                ["git", "cat-file", "-s", f"HEAD~1:{rel_path}"],
                capture_output=True, text=True, check=True, cwd=sim_repo,
            )
            size = int(r.stdout.strip())
            # Simpan dengan key = path relatif dari dalam sim_repo (forward slash)
            baseline_files[rel_path] = {
                "size_bytes": size,
                "size_history": [size],
            }
        except Exception:
            continue

    from datetime import datetime, timezone
    envelope = {
        "version": "7.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": baseline_files,
    }
    with open(baseline_path, "w", encoding="utf-8") as f:
        import json as _json
        _json.dump(envelope, f, indent=2)

    print(f"    [+] Baseline dibangun: {len(baseline_files)} file dari HEAD~1")

    # Salin csg.config.yaml ke dalam sim_repo agar CSG bisa membaca konfigurasi
    src_cfg = PROJECT_ROOT / "config-size-guard" / "csg.config.yaml"
    dst_cfg = sim_repo / "csg.config.yaml"
    if src_cfg.exists():
        import shutil
        shutil.copy2(src_cfg, dst_cfg)
        print(f"    [+] csg.config.yaml disalin ke repo simulasi")


def _result_key(filepath: str) -> str:
    """Key evaluasi: <folder_skenario>/<nama_file> (2 segmen terakhir path)."""
    parts = Path(filepath.replace("\\", "/")).parts
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    return parts[-1]


def load_ground_truth() -> dict[str, dict]:
    gt_map: dict[str, dict] = {}
    for cohort_label, csv_path in GT_FILES:
        if not csv_path.exists():
            raise FileNotFoundError(f"Ground truth tidak ditemukan: {csv_path}")
        with csv_path.open("r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                key = _result_key(row["filepath"])
                gt_map[key] = {
                    "expected_verdict": row["expected_verdict"],
                    "cohort": row.get("cohort") or cohort_label,
                }
    return gt_map


def run_scanner() -> list[dict]:
    print("[*] 2. CSG Memindai Repositori Simulasi...\n")
    sim_repo = PROJECT_ROOT / SCAN_ROOT
    csg_src = str(PROJECT_ROOT / "config-size-guard" / "src")
    cmd = [
        "python", "-m", "csg.cli", "check",
        "--paths", ".",
        "--format", "json",
        "--strict-format",
    ]
    import os
    env = os.environ.copy()
    env["PYTHONPATH"] = csg_src
    result = subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=str(sim_repo), encoding="utf-8", errors="replace",
        env=env,
    )

    parsed = []
    raw_events = []          # BARU: simpan SEMUA event mentah, bukan cuma csg_file_scan
    event_type_seen = set()  # BARU: untuk diagnosis

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        event_type_seen.add(event.get("event_type", "UNKNOWN"))
        raw_events.append(event)   # BARU: tangkap semua jenis event

        if event.get("event_type") != "csg_file_scan":
            continue
        fp = event.get("filepath", "")
        fp_norm = fp.replace("\\", "/").lstrip("./")
        if not fp_norm:
            continue
        parsed.append({
            "filepath": fp_norm,
            "verdict": event.get("severity", "PASS"),
        })

    # ---- BARU: diagnostik schema (tidak mengubah hasil skoring sama sekali) ----
    print(f"[diag] Jenis event_type yang muncul di stdout: {sorted(event_type_seen)}")
    if raw_events:
        sample = next((e for e in raw_events if e.get("event_type") == "csg_file_scan"), raw_events[0])
        print(f"[diag] Key yang tersedia pada event 'csg_file_scan': {sorted(sample.keys())}")

    # ---- BARU: dump semua event mentah untuk diperiksa manual ----
    dump_path = PROJECT_ROOT / "tests" / "csg_raw_events_dump.jsonl"
    with open(dump_path, "w", encoding="utf-8") as f:
        for e in raw_events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"[diag] {len(raw_events)} event mentah disimpan ke {dump_path}")

    if parsed:
        return parsed

    if result.stderr.strip():
        print("[!] ERROR INTERNAL CSG:")
        print(result.stderr[:500])
    else:
        print("[!] ERROR INTERNAL CSG: tidak ada event NDJSON di stdout.")
        print(result.stdout[:2000] if result.stdout else "(stdout kosong)")
    return []


def _is_positive_expected(verdict: str) -> bool:
    return verdict in ("WARN", "CRITICAL")


def _score_subset(
    results: list[dict],
    gt_subset: dict[str, dict],
) -> tuple[int, int, int, int, list[tuple[str, str]]]:
    tp = tn = fp = fn = 0
    failed: list[tuple[str, str]] = []
    by_key = {_result_key(r["filepath"]): r for r in results}

    for key, meta in gt_subset.items():
        expected = meta["expected_verdict"]
        pos_exp = expected in ("WARN", "CRITICAL") # Target Positif (Anomali)

        if key not in by_key:
            if pos_exp:
                fn += 1
                failed.append((key, f"Tidak discan (harus {expected})"))
            else:
                tn += 1 # Jika file sehat tidak discan/di-skip, kita anggap dia lolos (TN)
            continue

        predicted = by_key[key]["verdict"]
        pos_pred = predicted in ("WARN", "CRITICAL") # Prediksi Positif (Bahaya)

        if pos_exp and pos_pred:
            tp += 1
        elif not pos_exp and not pos_pred:
            tn += 1
        elif not pos_exp and pos_pred:
            fp += 1
            failed.append((key, f"Alarm Palsu (harus PASS, dapat {predicted})"))
        else:
            fn += 1
            failed.append((key, f"Kebobolan (harus {expected}, dapat {predicted})"))

    return tp, tn, fp, fn, failed

def _print_metrics(title: str, tp: int, tn: int, fp: int, fn: int, failed: list) -> None:
    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0 # TAMBAHAN METRIK FPR

    print(f"\n--- {title} ({total} spesimen) ---")
    print(f"  TN: {tn}  |  TP: {tp}  |  FP: {fp}  |  FN: {fn}")
    print(f"  Precision: {precision * 100:.2f}%  |  Recall: {recall * 100:.2f}%")
    print(f"  F1-Score:  {f1 * 100:.2f}%   |  FPR: {fpr * 100:.2f}%")
    if failed:
        print("  Miss:")
        for path, reason in failed[:10]:
            print(f"    - {path}: {reason}")
        if len(failed) > 10:
            print(f"    ... dan {len(failed) - 10} lainnya")

def evaluate(results: list[dict]) -> None:
    gt_map = load_ground_truth()
    print(f"[*] Ground truth dimuat: {len(gt_map)} label (target: 112)")

    cohort_specs = [
        ("1_benign_standard [FP]", lambda k: k.startswith("1_benign_standard/")),
        ("2_config_drift_simulated [TP/FN]", lambda k: k.startswith("S")),
        ("3_real_postmortem_replicas", lambda k: "/" in k and k.split("/")[0].startswith("R")),
    ]

    grand_tp = grand_tn = grand_fp = grand_fn = 0
    all_failed: list[tuple[str, str]] = []

    print("\n==================================================")
    print(" HASIL EVALUASI CONFIG SIZE GUARD (CSG)")
    print("==================================================")

    for title, key_pred in cohort_specs:
        subset_gt = {k: v for k, v in gt_map.items() if key_pred(k)}
        subset_results = [r for r in results if key_pred(_result_key(r["filepath"]))]
        tp, tn, fp, fn, failed = _score_subset(subset_results, subset_gt)
        _print_metrics(title, tp, tn, fp, fn, failed)
        grand_tp += tp
        grand_tn += tn
        grand_fp += fp
        grand_fn += fn
        all_failed.extend(failed)

    scanned_keys = {_result_key(r["filepath"]) for r in results}
    missing = [k for k in gt_map if k not in scanned_keys]
    if missing:
        print(f"\n[!] {len(missing)} label ground truth tidak ada di hasil scan:")
        for k in missing[:8]:
            print(f"    - {k}")
        if len(missing) > 8:
            print(f"    ... dan {len(missing) - 8} lainnya")

    print("\n--- AGREGAT (semua kohort) ---")
    _print_metrics("TOTAL", grand_tp, grand_tn, grand_fp, grand_fn, all_failed)
    print("==================================================")


if __name__ == "__main__":
    setup_arena()
    scan_results = run_scanner()
    if not scan_results:
        print("[!] Gagal memproses data pemindaian.")
    else:
        print(f"[*] Event scan terparse: {len(scan_results)}")
        evaluate(scan_results)