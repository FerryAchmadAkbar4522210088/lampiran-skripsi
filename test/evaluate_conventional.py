"""
evaluate_conventional.py

Evaluasi langsung 5 alat validasi konvensional terhadap 3 kohort dataset (112 spesimen).

Dirancang apple-to-apple dengan evaluate_csg.py:
  - Setiap alat dijalankan langsung via subprocess terhadap setiap file
  - Exit Code dipetakan ke Confusion Matrix tanpa perantara apapun
  - Ground truth dibaca dari CSV yang SAMA dengan evaluate_csg.py
  - Logika _result_key, _score_subset, _print_metrics identik

Kohort dataset:
  1_benign_standard              (50) PASS           → ukur FPR
  2_config_drift_simulated       (50) WARN/CRITICAL  → ukur TPR/FNR
  3_real_postmortem_replicas     (12) PASS/WARN/CRIT → validasi insiden nyata

Mekanisme pemetaan:
  Exit Code = 0       → Prediksi Negatif (alat meloloskan file)
  Exit Code > 0       → Prediksi Positif (alat mendeteksi anomali / memblokir)
  N/A (fmt tdk supp.) → Prediksi Negatif (alat tidak dapat memproses file)
  TIMEOUT / ERROR     → Prediksi Positif (pipeline CI/CD akan terhenti)

Cara pakai (dari dalam folder benchmark/):
  python evaluate_conventional.py
  python evaluate_conventional.py --dataset path/ke/evaluation_dataset
  python evaluate_conventional.py --skip-preflight   (lewati preflight check, TIDAK disarankan)
"""

import subprocess
import csv
import sys
import shutil
import time
import argparse
from pathlib import Path

from fix_subprocess_windows import (
    run_subprocess_fixed,
    is_positive_pred_fixed,
    compute_coverage_rate,
)

# ──────────────────────────────── KONFIGURASI ────────────────────────────────

# Direktori root dataset (default: benchmark/evaluation_dataset/ relatif ke skrip ini)
_SCRIPT_DIR = Path(__file__).resolve().parent
DATASET_ROOT = _SCRIPT_DIR / ".." / "config-size-guard" / "tests" / "evaluation_dataset"

# Ground truth — file CSV identik dengan yang digunakan evaluate_csg.py
GT_FILES = [
    ("1_benign_standard (FP)",            DATASET_ROOT / "ground_truth_benign.csv"),
    ("2_config_drift_simulated (TP/FN)", DATASET_ROOT / "ground_truth_drift_scenarios.csv"),
    ("3_real_postmortem_replicas",        DATASET_ROOT / "ground_truth_postmortem_replicas.csv"),
]

# Direktori kohort yang dipindai
SCAN_DIRS = [
    DATASET_ROOT / "1_benign_standard",
    DATASET_ROOT / "2_config_drift_simulated",
    DATASET_ROOT / "3_real_postmortem_replicas",
]

# Alat yang dievaluasi
TOOLS = ["Yamllint", "Jsonlint", "Checkov", "OPA", "MegaLinter"]

# Format file yang didukung tiap alat
TOOL_FORMATS: dict[str, set[str]] = {
    "Yamllint":   {"YAML", "YML"},
    "Jsonlint":   {"JSON", "JSON5", "JSONC"},
    "Checkov":    {"YAML", "YML", "JSON", "JSON5", "JSONC", "HCL", "TF", "TFVARS"},
    "OPA":        {"YAML", "YML", "JSON", "JSON5", "JSONC"},
    "MegaLinter": {"YAML", "YML", "JSON", "JSON5", "JSONC"},
}

# Timeout per file per alat (detik).
TOOL_TIMEOUT = 120

# Path policy.rego untuk OPA — harus ada di direktori skrip ini
OPA_POLICY_PATH = _SCRIPT_DIR / "policy.rego"


# ─────────────────────────── PREFLIGHT CHECK ─────────────────────────────────
#
# TUJUAN: sebelum membuang waktu memindai 112 file, pastikan dulu ke-5 alat
# BENAR-BENAR bisa dipanggil di environment ini. Kalau satu saja gagal, kita
# harus berhenti total dan bilang dengan jelas alat mana + kenapa — bukan
# membiarkan kegagalan panggilan itu diam-diam tercatat sebagai "N/A" atau
# "NOT_FOUND" lalu ikut dihitung ke Confusion Matrix seolah-olah tool
# benar-benar berjalan dan menjawab PASS. Itulah yang bikin metrik 0.00%
# menyesatkan pada evaluasi sebelumnya: bukan tool-nya yang buruk, tapi
# tool-nya tidak pernah benar-benar tereksekusi.
#
# PENTING soal Windows: perintah dipanggil dengan shell=True (bukan list
# argumen tanpa shell). Ini karena tool seperti npx/checkov/jsonlint biasanya
# terpasang sebagai shim ".cmd"/".bat" (bukan ".exe" murni), dan file semacam
# itu HANYA bisa dieksekusi lewat shell (cmd.exe) — bukan langsung lewat
# Windows CreateProcess. Kalau dipanggil tanpa shell=True, Anda akan dapat
# "FileNotFoundError: [WinError 2]" walau tool itu terpasang & bisa dijalankan
# manual dari terminal. run_benchmark.py sudah lebih dulu membuktikan ini
# (pakai shell=True dan Checkov berhasil dapat exit code asli).

PREFLIGHT_COMMANDS: dict[str, str] = {
    "Yamllint":   "yamllint --version",
    "Checkov":    "checkov --version",
    "OPA":        "opa version",
    # CATATAN: MegaLinter sekarang dipanggil lewat 'docker run' langsung
    # (bukan lagi npx mega-linter-runner), karena npx/node terbukti bisa
    # memicu prompt interaktif yang membuat proses macet tanpa batas waktu
    # (github.com/oxsecurity/megalinter/issues/3060). Preflight cukup
    # memastikan docker & image-nya siap.
    "MegaLinter": "docker image inspect oxsecurity/megalinter:v8",
}


def _jsonlint_smoke_test() -> tuple[int, str, str, str]:
    """
    Smoke test khusus Jsonlint. TIDAK memakai '--version', karena package
    'jsonlint' di npm terbukti mengembalikan exit code 1 untuk --version
    walau ia berhasil jalan dan mencetak versinya (quirk package ini, bukan
    tanda rusak). Jadi kita uji dengan skenario nyata: lint 1 file JSON kecil
    yang valid, dan exit code 0 barulah dianggap sehat -- ini representatif
    dengan bagaimana Jsonlint benar-benar dipakai di evaluasi (_get_exit_code).
    """
    import tempfile
    tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            f.write('{"ok": true}')
            tmp_path = f.name

        cmd_str = f'jsonlint -q "{tmp_path}"'
        result = subprocess.run(
            cmd_str, shell=True, capture_output=True, text=True, timeout=30,
        )
        return result.returncode, cmd_str, result.stdout, result.stderr
    finally:
        if tmp_path:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except Exception:
                pass


def preflight_check_tools(skip: bool = False) -> None:
    """
    Verifikasi tiap alat di TOOLS benar-benar terpasang dan bisa dieksekusi.
    Jika ADA SATU SAJA yang gagal, cetak alasan yang jelas untuk semua alat
    yang bermasalah lalu hentikan program (sys.exit(1)) — tidak lanjut ke
    tahap scan/evaluate sama sekali.
    """
    print("=" * 56)
    print(" PREFLIGHT CHECK — memverifikasi 5 alat sebelum evaluasi")
    print("=" * 56)

    if skip:
        print("[!] Preflight check dilewati (--skip-preflight). "
              "Hasil evaluasi TIDAK terjamin valid.\n")
        return

    problems: list[tuple[str, str, str]] = []

    for tool in TOOLS:
        # Jsonlint pakai smoke test khusus (lint file JSON valid), bukan '--version'
        if tool == "Jsonlint":
            try:
                code, cmd_str, out, err = _jsonlint_smoke_test()
            except subprocess.TimeoutExpired:
                reason = "Timeout >30s saat smoke test Jsonlint."
                problems.append((tool, "TIMEOUT", reason))
                print(f"  [GAGAL] {tool:<12} -> {reason}")
                continue
            except Exception as e:
                reason = f"Error tak terduga saat smoke test Jsonlint: {e}"
                problems.append((tool, "ERROR", reason))
                print(f"  [GAGAL] {tool:<12} -> {reason}")
                continue

            if code != 0:
                snip = (err or out or "").strip()[:200]
                reason = (
                    f"'{cmd_str}' terhadap JSON valid harus exit 0, tapi dapat "
                    f"{code}. stderr/stdout: {snip or '(kosong)'}"
                )
                problems.append((tool, "NONZERO_EXIT", reason))
                print(f"  [GAGAL] {tool:<12} -> {reason}")
            else:
                print(f"  [OK]    {tool:<12} -> berhasil lint file JSON valid (smoke test)")
            continue

        cmd_str = PREFLIGHT_COMMANDS[tool]
        exe = cmd_str.split()[0]

        # CATATAN PENTING (Windows): banyak tool CLI (npx, checkov, jsonlint, dll.)
        # terpasang sebagai shim ".cmd"/".bat", BUKAN ".exe" murni. File semacam
        # ini hanya bisa dieksekusi lewat shell (cmd.exe), bukan langsung lewat
        # Windows CreateProcess. Karena itu kita WAJIB pakai shell=True di sini —
        # sama seperti run_benchmark.py, yang terbukti berhasil memanggil Checkov
        # dan menghasilkan exit code asli (0/1), bukan NOT_FOUND. Kalau baris ini
        # diganti shell=False lagi, tool berbasis .cmd/.bat akan gagal palsu
        # dengan WinError 2 walau file-nya ada dan bisa dipanggil manual dari
        # terminal.
        resolved = shutil.which(exe)  # hanya untuk info tambahan, bukan penentu lolos/gagal

        try:
            result = subprocess.run(
                cmd_str,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            reason = f"Timeout >30s saat memanggil '{cmd_str}'."
            problems.append((tool, "TIMEOUT", reason))
            print(f"  [GAGAL] {tool:<12} -> {reason}")
            continue
        except Exception as e:
            reason = f"Error tak terduga saat memanggil '{cmd_str}': {e}"
            problems.append((tool, "ERROR", reason))
            print(f"  [GAGAL] {tool:<12} -> {reason}")
            continue

        if result.returncode != 0:
            stderr_snip = (result.stderr or result.stdout or "").strip()[:200]
            reason = (
                f"'{cmd_str}' selesai dengan exit code {result.returncode} "
                f"(diharapkan 0). Kemungkinan: command tidak dikenali shell "
                f"(tool memang belum terpasang), atau tool butuh dependensi lain "
                f"(mis. Docker) yang belum siap. stderr/stdout: {stderr_snip or '(kosong)'}"
            )
            problems.append((tool, "NONZERO_EXIT", reason))
            print(f"  [GAGAL] {tool:<12} -> {reason}")
        else:
            lokasi = resolved or "(ditemukan lewat shell, path pasti tidak diketahui shutil.which)"
            print(f"  [OK]    {tool:<12} -> {lokasi}")

    if problems:
        print("\n" + "=" * 56)
        print(" EVALUASI DIHENTIKAN — ADA ALAT YANG TIDAK AKTIF")
        print("=" * 56)
        print(f"  {len(problems)} dari {len(TOOLS)} alat gagal saat preflight check:\n")
        for tool, code, reason in problems:
            print(f"  - {tool} [{code}]")
            print(f"      {reason}")
        print(
            "\n[!] Evaluasi dibatalkan. Confusion Matrix tidak akan dihitung "
            "karena kegagalan panggilan alat (infra) akan bercampur dengan "
            "hasil linting yang sesungguhnya, membuat Precision/Recall/F1 "
            "tampak buruk padahal tool memang tidak pernah berjalan.\n"
            "Perbaiki instalasi / PATH / dependensi alat di atas, lalu "
            "jalankan ulang skrip ini."
        )
        sys.exit(1)

    print(f"\n[*] Semua {len(TOOLS)} alat aktif dan siap dipanggil.\n")


# ─────────────────────────── FORMAT DETECTION ────────────────────────────────

def _get_format(filepath: Path) -> str | None:
    """
    Deteksi format file dari nama dan ekstensi.
    Logika identik dengan get_file_format() di run_benchmark.py.

    CATATAN PERBAIKAN: sebelumnya deteksi ENV hanya mengenali nama file yang
    DIAWALI ".env" (mis. ".env.local"), sehingga file seperti
    "elegantadmin.env.production" (titik env di tengah nama) tidak pernah
    terdeteksi -> 4 label ground truth hilang dari hasil scan. Sekarang
    dicocokkan dengan substring seperti di run_benchmark.py agar konsisten.
    """
    name = filepath.name.lower()

    if "dockerfile" in name:
        return "DOCKERFILE"
    if name in (".gitconfig",) or name.endswith(".gitconfig"):
        return "GITCONFIG"
    if ".env" in name:
        if "production" in name or "prod" in name:
            return "ENV_PROD"
        if "development" in name or "dev" in name:
            return "ENV_DEV"
        if "staging" in name:
            return "ENV_STAGING"
        return "ENV"

    ext = filepath.suffix.lstrip(".").lower()
    VALID_EXTS = {
        "yaml", "yml", "json", "json5", "jsonc", "xml", "toml",
        "ini", "conf", "cfg", "properties", "env", "hcl", "tf",
        "tfvars", "kdl", "pbtxt",
    }
    return ext.upper() if ext in VALID_EXTS else None


# ─────────────────────────── RESULT KEY ──────────────────────────────────────

def _result_key(filepath: str) -> str:
    """
    Key evaluasi: <folder_skenario>/<nama_file> (2 segmen terakhir path).
    """
    parts = Path(filepath.replace("\\", "/")).parts
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    return parts[-1]


# ─────────────────────────── TOOL RUNNER ─────────────────────────────────────

def _get_exit_code(tool: str, filepath: Path, fmt: str) -> int | str:
    """
    Jalankan satu alat terhadap satu file menggunakan run_subprocess_fixed Windows.
    """
    if fmt not in TOOL_FORMATS[tool]:
        return "N/A"

    fp = str(filepath)

    if tool == "Yamllint":
        code, _ = run_subprocess_fixed(["yamllint", fp])

    elif tool == "Jsonlint":
        code, _ = run_subprocess_fixed(["jsonlint", "-q", fp])

    elif tool == "Checkov":
        code, _ = run_subprocess_fixed(["checkov", "-f", fp, "--quiet"])

    elif tool == "OPA":
        if not OPA_POLICY_PATH.exists():
            return "NO_POLICY"
        code, _ = run_subprocess_fixed([
            "opa", "eval",
            "-i", fp,
            "-d", str(OPA_POLICY_PATH),
            "data.skripsi.benchmark.allow",
            "--fail",
        ])

    elif tool == "MegaLinter":
        # CATATAN PENTING: 'npx mega-linter-runner' bisa memicu prompt
        # interaktif (mis. memilih registry docker) pada kondisi tertentu
        # (lihat: github.com/oxsecurity/megalinter/issues/3060). Karena
        # dipanggil lewat subprocess tanpa terminal asli, prompt itu
        # menunggu input yang tidak pernah datang -> proses macet total
        # (terbukti dari docker ps -a yang kosong: docker run bahkan tidak
        # pernah sempat terpanggil). Solusinya: panggil 'docker run' LANGSUNG
        # ke image yang sudah ter-pull (oxsecurity/megalinter:v8), melewati
        # npx/node sepenuhnya. Ini juga sekaligus menghindari masalah shim
        # .cmd di Windows karena docker.exe adalah binary asli.
        target_dir = str(filepath.parent)
        filename_escaped = filepath.name.replace('"', '\\"')
        cmd_str = (
            f'docker run --rm '
            f'-v "{target_dir}:/tmp/lint:rw" '
            f'-e "ENABLE=YAML,JSON" '
            f'-e "VALIDATE_ALL_CODEBASE=true" '
            f'-e "FILTER_REGEX_INCLUDE={filename_escaped}" '
            f'oxsecurity/megalinter:v8'
        )
        code, _ = run_subprocess_fixed(["docker", "run", "--rm",
            "-v", f"{target_dir}:/tmp/lint:rw",
            "-e", "ENABLE=YAML,JSON",
            "-e", "VALIDATE_ALL_CODEBASE=true",
            "-e", f"FILTER_REGEX_INCLUDE={filename_escaped}",
            "oxsecurity/megalinter:v8",
        ])
    else:
        return "N/A"

    return code


# ─────────────────────────── GROUND TRUTH ────────────────────────────────────

def load_ground_truth() -> dict[str, dict]:
    """
    Muat ground truth dari 3 CSV kohort.
    """
    gt_map: dict[str, dict] = {}
    for cohort_label, csv_path in GT_FILES:
        if not csv_path.exists():
            raise FileNotFoundError(
                f"Ground truth tidak ditemukan: {csv_path}\n"
                f"Pastikan DATASET_ROOT mengarah ke direktori yang benar."
            )
        with csv_path.open("r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                key = _result_key(row["filepath"])
                gt_map[key] = {
                    "expected_verdict": row["expected_verdict"],
                    "cohort": row.get("cohort") or cohort_label,
                }
    return gt_map


# ─────────────────────────── FILE COLLECTION ─────────────────────────────────

def collect_files() -> list[Path]:
    """
    Kumpulkan semua file berformat valid dari 3 direktori kohort.
    """
    files: list[Path] = []
    for scan_dir in SCAN_DIRS:
        if not scan_dir.exists():
            print(f"[!] Direktori kohort tidak ditemukan: {scan_dir}")
            continue
        for fp in sorted(scan_dir.rglob("*")):
            if fp.is_file() and _get_format(fp) is not None:
                files.append(fp)
    return files


# ─────────────────────────── SCANNER ─────────────────────────────────────────

def run_tools(files: list[Path]) -> dict[str, dict[str, int | str]]:
    """
    Jalankan semua 5 alat terhadap semua file.
    """
    tool_results: dict[str, dict[str, int | str]] = {tool: {} for tool in TOOLS}
    total = len(files)

    for idx, fp in enumerate(files, 1):
        fmt = _get_format(fp)
        key = _result_key(str(fp))

        sys.stdout.write(f"\r  [{idx:3d}/{total}] {key:<55} [{fmt}]")
        sys.stdout.flush()

        for tool in TOOLS:
            exit_code = _get_exit_code(tool, fp, fmt)
            tool_results[tool][key] = exit_code

    print()
    return tool_results


# ─────────────────────────── SCORING ─────────────────────────────────────────

def _score_subset(
    tool_results: dict[str, int | str],
    gt_subset: dict[str, dict],
) -> tuple[int, int, int, int, list[tuple[str, str]]]:
    """
    Hitung TP, TN, FP, FN dengan mengecualikan INFRA_FAIL.
    """
    tp = tn = fp = fn = 0
    failed: list[tuple[str, str]] = []

    for key, meta in gt_subset.items():
        expected = meta["expected_verdict"]
        pos_exp  = expected in ("WARN", "CRITICAL")

        exit_code = tool_results.get(key)
        pos_pred, category = is_positive_pred_fixed(exit_code)

        if category == "INFRA_FAIL":
            continue   # PENTING: Mengecualikan kegagalan infrastruktur Windows

        if pos_exp and pos_pred:
            tp += 1
        elif not pos_exp and not pos_pred:
            tn += 1
        elif not pos_exp and pos_pred:
            fp += 1
            failed.append((key, f"Alarm Palsu → harus PASS, exit code: {exit_code}"))
        else:
            fn += 1
            failed.append((key, f"Kebobolan   → harus {expected}, exit code: {exit_code}"))

    return tp, tn, fp, fn, failed


def _print_metrics(
    title: str,
    tp: int, tn: int, fp: int, fn: int,
    failed: list[tuple[str, str]],
) -> None:
    """Cetak metrik Confusion Matrix."""
    total     = tp + tn + fp + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0)
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print(f"\n--- {title} ({total} spesimen) ---")
    print(f"  TN: {tn}  |  TP: {tp}  |  FP: {fp}  |  FN: {fn}")
    print(f"  Precision: {precision * 100:.2f}%  |  Recall: {recall * 100:.2f}%")
    print(f"  F1-Score:  {f1 * 100:.2f}%   |  FPR: {fpr * 100:.2f}%")
    if failed:
        print("  Miss:")
        for path, reason in failed[:10]:
            print(f"     - {path}: {reason}")
        if len(failed) > 10:
            print(f"     ... dan {len(failed) - 10} lainnya")


# ─────────────────────────── EVALUATOR ───────────────────────────────────────

COHORT_SPECS = [
    (
        "1_benign_standard [FP]",
        lambda k: k.startswith("1_benign_standard/"),
    ),
    (
        "2_config_drift_simulated [TP/FN]",
        lambda k: k.startswith("S"),
    ),
    (
        "3_real_postmortem_replicas",
        lambda k: "/" in k and k.split("/")[0].startswith("R"),
    ),
]


def evaluate(tool_results: dict[str, dict[str, int | str]]) -> None:
    """
    Evaluasi semua alat terhadap ground truth dan cetak Coverage Rate.
    """
    gt_map = load_ground_truth()
    print(f"[*] Ground truth dimuat: {len(gt_map)} label (target: 112)\n")

    print("=" * 56)
    print(" HASIL EVALUASI 5 ALAT KONVENSIONAL")
    print("=" * 56)

    summary: list[tuple[str, float, float, float, float]] = []

    for tool in TOOLS:
        t_results = tool_results[tool]

        print(f"\n{'-' * 56}")
        print(f"  ALAT: {tool.upper()}")
        print(f"{'-' * 56}")

        grand_tp = grand_tn = grand_fp = grand_fn = 0
        all_failed: list[tuple[str, str]] = []

        for title, key_pred in COHORT_SPECS:
            subset_gt = {k: v for k, v in gt_map.items() if key_pred(k)}
            tp, tn, fp, fn, failed = _score_subset(t_results, subset_gt)
            _print_metrics(title, tp, tn, fp, fn, failed)
            grand_tp += tp
            grand_tn += tn
            grand_fp += fp
            grand_fn += fn
            all_failed.extend(failed)

        scanned_keys = set(t_results.keys())
        missing_keys = [k for k in gt_map if k not in scanned_keys]
        if missing_keys:
            print(f"\n  [!] {len(missing_keys)} label ground truth tidak dipindai oleh {tool}:")
            for k in missing_keys[:5]:
                print(f"      - {k}")
            if len(missing_keys) > 5:
                print(f"      ... dan {len(missing_keys) - 5} lainnya")

        _print_metrics(
            f"AGREGAT {tool.upper()}",
            grand_tp, grand_tn, grand_fp, grand_fn,
            all_failed,
        )

        total     = grand_tp + grand_tn + grand_fp + grand_fn
        precision = grand_tp / (grand_tp + grand_fp) if (grand_tp + grand_fp) > 0 else 0.0
        recall    = grand_tp / (grand_tp + grand_fn) if (grand_tp + grand_fn) > 0 else 0.0
        f1        = (2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0)
        fpr       = grand_fp / (grand_fp + grand_tn) if (grand_fp + grand_tn) > 0 else 0.0
        summary.append((tool, precision * 100, recall * 100, f1 * 100, fpr * 100))

    print("\n" + "=" * 56)
    print(" RINGKASAN KOMPARATIF — 5 ALAT KONVENSIONAL")
    print(f" {'Alat':<15} {'Precision':>10} {'Recall':>8} {'F1':>8} {'FPR':>8}")
    print("-" * 56)
    for tool, prec, rec, f1, fpr in summary:
        print(f" {tool:<15} {prec:>9.2f}%  {rec:>7.2f}%  {f1:>7.2f}%  {fpr:>7.2f}%")
    print("=" * 56)
    print("[*] Bandingkan tabel ini dengan output evaluate_csg.py untuk")
    print("    melihat selisih performa CSG vs alat konvensional.")

    # LAPORAN COVERAGE RATE DENGAN POSISI YANG BENAR
    print("\n" + "=" * 56)
    print(" COVERAGE RATE — Seberapa Sering Tool Benar-Benar Jalan")
    print("=" * 56)
    for tool in TOOLS:
        all_codes = list(tool_results[tool].values())
        cov = compute_coverage_rate(all_codes)
        print(f"  {tool:12s}: {cov['coverage_pct']:5.1f}% "
              f"({cov['real_runs']}/{cov['total']} file benar-benar diproses, "
              f"{cov['infra_fail']} infra fail, {cov['format_na']} format tidak didukung)")


# ─────────────────────────── ENTRY POINT ─────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluasi 5 alat konvensional.")
    parser.add_argument("--dataset", default=None, help="Path ke direktori evaluation_dataset")
    parser.add_argument(
        "--skip-preflight", action="store_true",
        help="Lewati preflight check alat (TIDAK disarankan, hanya untuk debugging).",
    )
    args = parser.parse_args()

    if args.dataset:
        global DATASET_ROOT, GT_FILES, SCAN_DIRS
        DATASET_ROOT = Path(args.dataset).resolve()
        GT_FILES = [
            ("1_benign_standard (FP)",            DATASET_ROOT / "ground_truth_benign.csv"),
            ("2_config_drift_simulated (TP/FN)", DATASET_ROOT / "ground_truth_drift_scenarios.csv"),
            ("3_real_postmortem_replicas",        DATASET_ROOT / "ground_truth_postmortem_replicas.csv"),
        ]
        SCAN_DIRS = [
            DATASET_ROOT / "1_benign_standard",
            DATASET_ROOT / "2_config_drift_simulated",
            DATASET_ROOT / "3_real_postmortem_replicas",
        ]

    print(f"[*] Dataset root : {DATASET_ROOT}")
    print(f"[*] OPA policy   : {OPA_POLICY_PATH}")
    print(f"[*] Tool timeout : {TOOL_TIMEOUT}s per file\n")

    # 0. PREFLIGHT CHECK — berhenti total kalau ada alat yang tidak aktif
    preflight_check_tools(skip=args.skip_preflight)

    print("[*] 1. Mengumpulkan file dataset...")
    files = collect_files()
    if not files:
        print("[!] Tidak ada file yang ditemukan. Periksa DATASET_ROOT dan SCAN_DIRS.")
        sys.exit(1)
    print(f"    Ditemukan {len(files)} file di 3 kohort.\n")

    print("[*] 2. Menjalankan 5 alat konvensional terhadap setiap file...")
    print(f"    (timeout per file: {TOOL_TIMEOUT}s — harap tunggu)\n")
    tool_results = run_tools(files)

    print(f"\n[*] 3. Menghitung Confusion Matrix per alat per kohort...\n")
    evaluate(tool_results)


if __name__ == "__main__":
    main()