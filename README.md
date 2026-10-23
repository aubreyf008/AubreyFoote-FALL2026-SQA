# AubreyFoote-FALL2026-SQA

Software Quality Assurance (COMP 5710/6710), Fall 2026 course project.

## Team

**Team name:** AubreyFoote

| Member | Email |
|---|---|
| Aubrey Foote | aubreyf008@gmail.com |

## What this repo contains

This repo starts from the **SLI-KUBE / KubeSec** project, a security-smell scanner for Kubernetes manifests. The original README is kept in [ORIGINAL_README.md](ORIGINAL_README.md). These quality assurance activities were added:

| Activity | Where |
|---|---|
| Fuzzing of 10 methods (4.a) | [`fuzz.py`](fuzz.py) → writes `logs/fuzz_report.md`, `logs/fuzz_crashes.csv` |
| Forensics logging in 10 methods (4.b) | [`forensics.py`](forensics.py) + the changed methods in `parser.py`, `scanner.py`, `graphtaint.py`, `main.py` → writes `logs/forensics.log` |
| Continuous integration (4.c) | [`.github/workflows/sqa.yml`](.github/workflows/sqa.yml) |
| Report | [`SQA-REPO.md`](SQA-REPO.md) |

## Running locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-sqa.txt
brew install yq            # or: sudo snap install yq  (the scanner calls yq)

python fuzz.py             # fuzz 10 methods
python main.py TEST_ARTIFACTS   # run the scanner (produces logs/forensics.log)
python TEST_PARSING.py     # existing unit tests
```
