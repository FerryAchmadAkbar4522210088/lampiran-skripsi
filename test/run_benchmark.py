# run_benchmark.py
# Benchmark 5 alat konvensional terhadap dataset yang SAMA dengan evaluate_csg.py
# Dataset: tests/evaluation_dataset/ (50 benign + 50 drift + 12 postmortem = 112 file)
# Jalankan dari dalam folder benchmark/:
#   cd benchmark && python run_benchmark.py

import os
import subprocess
import csv
import time
from pathlib import Path

# --- KONFIGURASI TARGET ---
TARGET_DIRS = [
    "benchmark/tests/evaluation_dataset/1_benign_standard",
    "benchmark/tests/evaluation_dataset/2_config_drift_simulated",
    "tests/evaluation_dataset/3_real_postmortem_replicas",
]

COHORT_MAP = {
    "1_benign_standard":          "1_benign_standard",
    "2_config_drift_simulated":   "2_config_drift_simulated",
    "3_real_postmortem_replicas": "3_real_postmortem_replicas",
}

OUTPUT_FILE = "benchmark_results_grand_final.csv"

_SCRIPT_DIR = Path(__file__).resolve().parent
OPA_POLICY  = str(_SCRIPT_DIR / "policy.rego")


def run_command(command, custom_timeout=180):
    start_time = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=custom_timeout,
        )
        execution_time = time.perf_counter() - start_time
        log_lines = len(result.stdout.splitlines()) + len(result.stderr.splitlines())
        return result.returncode, round(execution_time, 4), log_lines

    except subprocess.TimeoutExpired:
        return "TIMEOUT", ">180s", 0
    except Exception:
        return "ERROR", 0, 0


_EXT_MAP = {
    ".yaml": "YAML", ".yml": "YML", ".json": "JSON",
    ".json5": "JSON5", ".jsonc": "JSONC", ".toml": "TOML",
    ".xml": "XML", ".ini": "INI", ".cfg": "CFG",
    ".conf": "CONF", ".properties": "PROPERTIES",
    ".env": "ENV", ".hcl": "HCL",
    ".tf": "TF", ".tfvars": "TFVARS",
    ".pbtxt": "PBTXT",
    ".kdl": "KDL",
    ".gitconfig": "GITCONFIG",
    ".lock": "LOCK", ".sum": "SUM",
}

_EXACT_NAME_MAP = {
    "dockerfile": "DOCKERFILE",
    "containerfile": "DOCKERFILE",
    "makefile": "MAKEFILE",
    "procfile": "PROCFILE",
    "vagrantfile": "VAGRANTFILE",
    "jenkinsfile": "JENKINSFILE",
    "codeowners": "CODEOWNERS",
    "cname": "CNAME",
}


def get_file_format(filename: str) -> str | None:
    lower = filename.lower()
    path = Path(lower)

    if path.name in _EXACT_NAME_MAP:
        return _EXACT_NAME_MAP[path.name]

    if ".env" in lower:
        if "production" in lower or "prod" in lower:
            return "ENV_PROD"
        if "development" in lower or "dev" in lower:
            return "ENV_DEV"
        if "staging" in lower:
            return "ENV_STAGING"
        return "ENV"

    if "dockerfile" in lower:
        return "DOCKERFILE"

    suffix = path.suffix.lower()
    if suffix in _EXT_MAP:
        return _EXT_MAP[suffix]

    stem_suffix = Path(path.stem).suffix.lower()
    if stem_suffix in _EXT_MAP:
        return _EXT_MAP[stem_suffix]

    if filename.startswith(".") and not suffix:
        key = filename.lower()
        if "gitconfig" in key:
            return "GITCONFIG"

    return None


def get_cohort_name(filepath_str: str) -> str:
    norm = filepath_str.replace("\\", "/")
    for cohort_key in COHORT_MAP:
        if cohort_key in norm:
            return COHORT_MAP[cohort_key]
    return "unknown"


def get_expected_class(filepath_str: str, filename: str) -> str:
    norm = filepath_str.replace("\\", "/")
    is_benign_cohort = "1_benign_standard" in norm
    is_baseline_file = "baseline" in filename.lower()

    if is_benign_cohort or is_baseline_file:
        return "NORMAL_FILE"
    return "ANOMALY_FILE"


def main():
    results = []
    skipped = []

    print("=" * 60)
    print("Benchmark Grand Final — 5 Alat Konvensional")
    print("Dataset: tests/evaluation_dataset/ (3 kohort)")
    print("=" * 60)

    for directory in TARGET_DIRS:
        abs_dir = Path(directory).resolve()
        if not abs_dir.exists():
            print(f"[!] Folder tidak ditemukan: {abs_dir}")
            print("    Pastikan skrip dijalankan dari dalam folder 'benchmark/'.")
            continue

        for root, dirs, files in os.walk(abs_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]

            for file in sorted(files):
                filepath = os.path.join(root, file)
                file_format = get_file_format(file)

                if file_format is None:
                    skipped.append(filepath)
                    continue

                cohort_name    = get_cohort_name(filepath)
                expected_class = get_expected_class(filepath, file)

                print(f"-> [{cohort_name}] [{file_format}]: {file}")

                res_yamllint = res_jsonlint = res_checkov = \
                    res_opa = res_megalinter = ("N/A", "N/A", "N/A")

                if file_format in ("YAML", "YML"):
                    res_yamllint = run_command(f'yamllint "{filepath}"')

                if file_format in ("JSON", "JSONC", "JSON5"):
                    res_jsonlint = run_command(f'jsonlint -q "{filepath}"')

                res_checkov = run_command(f'checkov -f "{filepath}"')

                if file_format in ("YAML", "YML", "JSON"):
                    cmd_opa = (
                        f'opa eval -i "{filepath}" -d "{OPA_POLICY}" '
                        f'"data.skripsi.benchmark.allow" --fail'
                    )
                    res_opa = run_command(cmd_opa)

                # PENTING: MegaLinter dipanggil lewat 'docker run' LANGSUNG ke
                # image yang sudah ter-pull (oxsecurity/megalinter:v8), BUKAN
                # lewat 'npx mega-linter-runner'. npx/node terbukti bisa
                # memicu prompt interaktif (pilih registry docker) yang
                # membuat proses macet tanpa batas waktu ketika dipanggil
                # lewat subprocess tanpa terminal asli — lihat
                # github.com/oxsecurity/megalinter/issues/3060. Panggilan
                # docker run murni tidak pernah interaktif seperti itu.
                _target_dir = os.path.dirname(filepath)
                _filename_escaped = file.replace('"', '\\"')
                res_megalinter = run_command(
                    f'docker run --rm '
                    f'-v "{_target_dir}:/tmp/lint:rw" '
                    f'-e "ENABLE=YAML,JSON" '
                    f'-e "VALIDATE_ALL_CODEBASE=true" '
                    f'-e "FILTER_REGEX_INCLUDE={_filename_escaped}" '
                    f'oxsecurity/megalinter:v8'
                )

                results.append({
                    "Cohort":              cohort_name,
                    "Subfolder":           os.path.basename(root),
                    "Filename":            file,
                    "Expected_Class":      expected_class,
                    "Format":              file_format,
                    "Yamllint_ExitCode":   res_yamllint[0],
                    "Yamllint_Time":       res_yamllint[1],
                    "Yamllint_Alerts":     res_yamllint[2],
                    "Jsonlint_ExitCode":   res_jsonlint[0],
                    "Jsonlint_Time":       res_jsonlint[1],
                    "Jsonlint_Alerts":     res_jsonlint[2],
                    "Checkov_ExitCode":    res_checkov[0],
                    "Checkov_Time":        res_checkov[1],
                    "Checkov_Alerts":      res_checkov[2],
                    "OPA_ExitCode":        res_opa[0],
                    "OPA_Time":            res_opa[1],
                    "OPA_Alerts":          res_opa[2],
                    "MegaLinter_ExitCode": res_megalinter[0],
                    "MegaLinter_Time":     res_megalinter[1],
                    "MegaLinter_Alerts":   res_megalinter[2],
                })

    print(f"\nMenyimpan {len(results)} baris ke {OUTPUT_FILE}...")
    fieldnames = [
        "Cohort", "Subfolder", "Filename", "Expected_Class", "Format",
        "Yamllint_ExitCode", "Yamllint_Time", "Yamllint_Alerts",
        "Jsonlint_ExitCode", "Jsonlint_Time", "Jsonlint_Alerts",
        "Checkov_ExitCode",  "Checkov_Time",  "Checkov_Alerts",
        "OPA_ExitCode",      "OPA_Time",      "OPA_Alerts",
        "MegaLinter_ExitCode","MegaLinter_Time","MegaLinter_Alerts",
    ]
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"Benchmark Selesai! Total file diproses : {len(results)}")
    if skipped:
        print(f"File di-skip (format tidak dikenali): {len(skipped)}")
        for s in skipped[:10]:
            print(f"  - {os.path.basename(s)}")
        if len(skipped) > 10:
            print(f"  ... dan {len(skipped) - 10} lainnya")


if __name__ == "__main__":
    main()