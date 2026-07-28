# Struktur Dokumentasi Pengujian CSG

Dokumen ini menjelaskan struktur repositori pengujian untuk Config Size Guard (CSG) sesuai dengan skema evaluasi skripsi.

## 📦 1. Dataset uji (`config-size-guard/dataset-uji/`)

Spesimen statis untuk validasi deteksi (112 file):

- **`kohort-1/`** (50 spesimen, PASS) — kontrol negatif (benign)
- **`kohort-2/`** (50 spesimen, WARN/CRITICAL) — drift simulasi S1–S4
- **`kohort-3/`** (12 spesimen) — replika postmortem R1–R4

Ground truth label tetap di `tests/evaluation_dataset/ground_truth_*.csv` (monorepo).

**Menjalankan evaluasi lengkap (112 spesimen):**
```bash
python tests/evaluate_csg.py
```

Arena Git (`tests/growth_simulation_repo/`) dibangun via `tests/setup_growth_test.sh` dari `config-size-guard/dataset-uji/kohort-{1,2,3}`.

**Evaluasi di repo standalone GitHub (`config-size-guard/`):**
```bash
cd config-size-guard
python tests/evaluate_csg.py
```
