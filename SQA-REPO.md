# SQA Project Report

**Course:** Software Quality Assurance (COMP 5710/6710), Fall 2026
**Team:** AubreyFoote (Aubrey Foote, aubreyf008@gmail.com, working alone)
**Repository:** `AubreyFoote-FALL2026-SQA`
**Project under test:** SLI-KUBE (KubeSec), a Python tool that scans Kubernetes manifests and Helm charts for security smells such as hard-coded secrets, privileged containers and plain HTTP, and writes CSV and SARIF reports.

---

## 1. Summary

| Activity | What was done | Evidence |
|---|---|---|
| 1. Unpack project | Unpacked `slikube.zip`; imported unchanged as the first commit | commit "Import original slikube project" |
| 2. Spreadsheet | Team name and email entered in the course spreadsheet | (course spreadsheet) |
| 3. GitHub repo | Public repo `AubreyFoote-FALL2026-SQA` | this repository |
| 3. README | [`README.md`](README.md) lists team name and member | README.md |
| 4.a Fuzzing | [`fuzz.py`](fuzz.py) fuzzes 10 methods; **21 distinct crashes in 9 of 10 methods**, grouped into 7 bugs | [`logs/fuzz_report.md`](logs/fuzz_report.md), [`logs/fuzz_crashes.csv`](logs/fuzz_crashes.csv), [`logs/fuzz.log`](logs/fuzz.log) |
| 4.b Forensics | [`forensics.py`](forensics.py) plus logging added to 10 methods; one scan produces 7,704 events | [`logs/forensics.log`](logs/forensics.log) |
| 4.c CI | [`.github/workflows/sqa.yml`](.github/workflows/sqa.yml): 4 jobs (fuzz, forensics scan, unit tests, bandit) on every push and PR | Actions tab, `screenshots/` |
| 5. Report | This file | SQA-REPO.md |

Two bugs stopped the tool from running at all. Both were fixed so the forensics and CI activities could run (Section 5).

---

## 2. Activity 4.a: Fuzzing

### 2.1 Approach

`fuzz.py` is a random (black-box, mutation-based) fuzzer written with only the Python standard library, so it has no extra dependencies and runs the same locally and in CI. For each of the 10 target methods it runs 500 iterations (configurable). Each iteration builds an input from one of these sources:

- **Random Python values:** `None`, booleans, huge ints, `NaN`/`inf`, empty, huge and Unicode strings, bytes, and nested lists, tuples and dicts with non-string keys.
- **Manifest-shaped dicts:** realistic Kubernetes `Secret`/`ConfigMap`/`Pod` structures with random mutations.
- **Mutated real manifests:** every file in `TEST_ARTIFACTS/` used as a seed corpus, with byte flips, inserted YAML tokens (`: `, `- `, `&a`, `{{ .Values.x }}`, tabs, BOMs, NULs), chunk deletion and truncation. These go to `loadMultiYAML`, which reads from disk.
- **Odd but legal YAML:** `null:` keys, float keys, complex (`? [a, b]`) keys, the same int key in two documents, anchors and aliases, custom tags, deep flow nesting.
- **Deep nesting:** 1,100–3,000 levels, to probe recursion limits.

Every exception counts as a crash. Crashes are grouped by **(method, exception type, deepest project source line)**, so each group is one distinct defect. Each call has a **2-second time limit** (`signal.setitimer`), so hangs are recorded as `FuzzTimeout` instead of stalling the run. The seed is printed so any crash can be reproduced (`python fuzz.py --seed N`). In CI the seed is the run number, so every run explores new inputs.

### 2.2 The 10 fuzzed methods

| # | Method | Why chosen |
|---|---|---|
| 1 | `parser.loadMultiYAML` | Entry point for every file; reads untrusted input from disk |
| 2 | `parser.getSingleDict4MultiDocs` | Merges multi-document YAML; does key arithmetic |
| 3 | `parser.keyMiner` | Recursive search used by every taint check |
| 4 | `parser.getValuesRecursively` | Recursive generator used by every check |
| 5 | `parser.find_json_path_keys` | Regex over every key in a file |
| 6 | `parser.checkIfValidHelm` | Classifies files by path |
| 7 | `scanner.checkIfValidSecret` | Decides whether a value is a hard-coded secret |
| 8 | `scanner.scanForSecrets` | Core hard-coded-secret detector |
| 9 | `scanner.getItemFromSecret` | Unpacks secret scan results |
| 10 | `graphtaint.constructHelmString` | Builds Helm `.Values.x.y` strings for taint tracking |

### 2.3 Results (seed 2026, 500 runs per method)

| Method | Runs | Crashing runs | Distinct crashes |
|---|---|---|---|
| `parser.loadMultiYAML` | 500 | 45 | 2 |
| `parser.getSingleDict4MultiDocs` | 500 | 119 | 3 |
| `parser.keyMiner` | 500 | 76 | 2 |
| `parser.getValuesRecursively` | 500 | 87 | 2 |
| `parser.find_json_path_keys` | 500 | 203 | 2 |
| `parser.checkIfValidHelm` | 500 | 94 | 1 |
| `scanner.checkIfValidSecret` | 500 | **0** | 0 |
| `scanner.scanForSecrets` | 500 | 13 | 1 |
| `scanner.getItemFromSecret` | 500 | 345 | 5 |
| `graphtaint.constructHelmString` | 500 | 234 | 3 |

Full details with example inputs are in [`logs/fuzz_report.md`](logs/fuzz_report.md).

### 2.4 Bugs discovered by fuzzing

The 21 distinct crashes come from these 7 defects, ordered by impact.

**BUG-F1 (High): ordinary YAML with a non-string key crashes the whole scan.**
`find_json_path_keys` calls `regex_key_dot.match(key)` on every key, assuming it is a string. YAML allows `null`, float and complex keys. Each of these one-line files crashes `loadMultiYAML`, and so the whole `runScanner` run, with `TypeError: expected string or bytes-like object`:
```yaml
null: a          # key is None
1.5: a           # key is ScalarFloat
? [a, b]
: a              # key is CommentedKeySeq
```
(Fuzz crashes #6 and #15, `parser.py:272`.) Integer and boolean keys only survive because the code happens to check `isinstance(key, int)`.

**BUG-F2 (High, denial of service): deeply nested flow YAML takes exponential time.**
The 51-byte file `{{{{{{{{{{{{{{{{{{{{{{{{{}}}}}}}}}}}}}}}}}}}}}}}}}` makes `loadMultiYAML` run for minutes (fuzz crash #14, `FuzzTimeout`). Measured separately, the time grows about 9× for every 2 extra levels, in **both** ruamel.yaml's parser and the project's own `find_json_path_keys`:

| Nesting | ruamel parse | `find_json_path_keys` |
|---|---|---|
| 12 | 0.24 s | 0.05 s |
| 14 | 2.19 s | 0.49 s |
| 16 | 20.1 s | 4.36 s |

A single malicious manifest in a repository can therefore stall a CI pipeline that runs SLI-KUBE.

**BUG-F3 (Medium): `getSingleDict4MultiDocs` breaks on legal multi-document files.**
- The same integer key in two documents (`1: a` / `---` / `1: b`) raises `TypeError: unsupported operand type(s) for +: 'int' and 'str'`, because the de-duplication does `k_ + '.' + 'doc' + str(counter)` (crash #9).
- A document that is an empty list (`[]`) raises `IndexError` at `dic = dic[0]` (crash #7).
- A non-list argument raises `TypeError` (crash #8).

**BUG-F4 (Medium): unbounded recursion.**
`keyMiner`, `getValuesRecursively`, `find_json_path_keys` and `getKeyRecursively` (reached through `scanForSecrets`) all recurse once per nesting level, and raise `RecursionError` beyond roughly 1,000 levels (crashes #5, #10–13, #21). Nothing catches it, so one deep file aborts the scan.

**BUG-F5 (Medium): `constructHelmString` assumes a 3-tuple of strings.**
YAML integer keys such as list indexes reach it through `keyMiner`. String concatenation then raises `TypeError`, and tuples of the wrong length raise `ValueError` (crashes #1–3).

**BUG-F6 (Low): `checkIfValidHelm` requires a `str` path.**
Passing an int, `None` or a `pathlib.Path` raises `TypeError: argument of type ... is not iterable` (crash #4). `main.py` builds a `Path`, so this only works today because `os.walk` happens to return strings.

**BUG-F7 (Low): `getItemFromSecret` does no input validation.**
It assumes a dict of 3-tuples of lists and an int index of 0–2, and raises five kinds of exceptions otherwise (crashes #16–20). It is an internal helper, so the impact is low.

**No crash: `scanner.checkIfValidSecret`** survived every input, because it checks `isinstance(value, str)` before doing anything else. It is a good example of the defensive pattern the other methods lack.

---

## 3. Activity 4.b: Forensics

### 3.1 Approach

A shared logger in [`forensics.py`](forensics.py) writes to `logs/forensics.log`. Each line has this format:

```
timestamp | level | pid | module.function:line | event key=value ...
```

so a run can be reconstructed afterwards: who ran it, on what, what was skipped and why, what was found, and which outputs were produced. Design decisions:

- **Never log secret values.** The scanner exists to find passwords, so a forensic log that copied them would create a new leak. Only secret *key names* and counts are logged. For the same reason, HTTP findings log the key and not the URL, because URLs can contain `user:password@host`.
- **Fingerprint inputs and outputs.** Each file read, and the CSV and SARIF written, is logged with its size and SHA-256, so the log proves exactly what content was analyzed and produced.
- **Record decisions, not just events.** For example, the log says *why* a file was rejected as a manifest (`apiVersion_present=False kind_present=False`).
- **Keep exception detail.** The original code caught YAML errors and only printed `skipping`. The reason is now kept.
- **Log external commands.** `show_line_for_paths` runs `yq` through `subprocess`, and each exact command line is logged.
- `SLIKUBE_FORENSICS=0` turns logging off. `fuzz.py` uses this so 5,000 random calls don't bury the real audit trail.

### 3.2 The 10 instrumented methods

| # | Method | What is logged |
|---|---|---|
| 1 | `main.main` | Run start (user, host, Python, cwd, target dir); run end (files reported, CSV and SARIF paths with SHA-256, duration) |
| 2 | `scanner.runScanner` | Scan start (YAML files found); each file analyzed (helm/k8s flags); each invalid or weird file skipped; end summary (analyzed, invalid, SARIF results) |
| 3 | `scanner.scanSingleManifest` | Per file: k8s validity, secret key names, username/password/token counts, Helm taints |
| 4 | `scanner.scanForSecrets` | Keys examined; flagged key names with counts (no values) |
| 5 | `scanner.scanForHTTP` | Each plain-HTTP finding (key only); per-file count |
| 6 | `parser.loadMultiYAML` | File loaded with size and SHA-256; parse errors with exception type and message; documents loaded |
| 7 | `parser.checkParseError` | Parse failures with reason; result |
| 8 | `parser.checkIfValidK8SYaml` | Accept/reject decision with the reason flags |
| 9 | `parser.show_line_for_paths` | Exact external `yq` command; line numbers returned |
| 10 | `graphtaint.mineSecretGraph` | Secret keys, hierarchy entries, template matches, valid taints |

### 3.3 Example log lines (from `logs/forensics.log`)

```
... | INFO    | pid=… | main.main:65 | SLI-KUBE run started user=… host=… python=3.13.9 cwd=… target=…/TEST_ARTIFACTS
... | INFO    | pid=… | scanner.runScanner:644 | scan started dir=TEST_ARTIFACTS yaml_files_found=76
... | INFO    | pid=… | parser.loadMultiYAML:173 | loading YAML file=TEST_ARTIFACTS/absent.prome.yaml size=560B sha256=045a19a1…
... | INFO    | pid=… | parser.checkIfValidK8SYaml | k8s check file=TEST_ARTIFACTS/skampi.values.yaml valid=False apiVersion_present=False kind_present=False forbidden_kind=False
... | WARNING | pid=… | scanner.runScanner:739 | skipped invalid YAML file=TEST_ARTIFACTS/skampi.values.yaml
... | INFO    | pid=… | scanner.scanForSecrets:185 | secret scan keys_examined=104 flagged={'postgresql-user': (1, 0, 0), 'postgresql-password': (0, 1, 0), ...}
... | INFO    | pid=… | parser.show_line_for_paths | running external command: ['yq', '.spec | key | line ', 'TEST_ARTIFACTS/…']
... | INFO    | pid=… | scanner.runScanner:751 | scan finished dir=TEST_ARTIFACTS analyzed=56 invalid_total=20 weird_total=0 sarif_results=153
... | INFO    | pid=… | main.main:76 | SLI-KUBE run finished files_reported=56 csv=… (size=5772B sha256=9346…) sarif=… seconds=12.98
```

### 3.4 What the forensic log revealed

Reading the log turned up three problems that weren't visible before:

1. **Each file is parsed about 26 times.** One scan of 76 files logged **2,006** `loadMultiYAML` calls. Every `scanFor*` check reloads and re-parses the file from disk instead of reusing the parsed dict. Parsing once per file would make the scan much faster.
2. **20 of 76 files (26%) are skipped silently.** The original console output just said `Invalid YAML`. The log now records the reason, usually Helm `values.yaml` files with no `apiVersion` or `kind`.
3. **Some findings have no line number.** 10 of 140 `yq` lookups returned `lines=[]`. In those cases `scanForHTTP` used a list index (`key=2`) as the key name, so the HTTP-without-TLS finding gets no SARIF location. This is the same root cause as the `KeyError` fixed in Section 5.

---

## 4. Activity 4.c: Continuous Integration

[`.github/workflows/sqa.yml`](.github/workflows/sqa.yml) runs on every `push`, every `pull_request`, and on demand (`workflow_dispatch`). It has four parallel jobs on `ubuntu-latest` with Python 3.13 and pinned dependencies ([`requirements-sqa.txt`](requirements-sqa.txt)):

| Job | What it does | Output |
|---|---|---|
| **Fuzz 10 methods** | `python fuzz.py --iterations 500 --seed <run number>` | Fuzz report in the run summary; `fuzz-logs` artifact |
| **Run scanner with forensic logging** | Ensures `yq` is present, runs `main.py TEST_ARTIFACTS` | Event counts, warnings and start/end lines in the run summary; `forensics-logs` artifact (log, CSV, SARIF, console output) |
| **Existing unit tests** | `python TEST_PARSING.py` (23 tests) | Pass/fail |
| **Security static analysis (bandit)** | `bandit -r .` | Metrics in the run summary; `bandit-report` artifact |

Design decisions:
- **Fuzzing reports crashes without failing the build.** Crashes are expected findings that get triaged here, and a permanently red build would hide new regressions. `python fuzz.py --fail-on-crash` exists for when the bugs are fixed and crashes should block merges.
- **The seed changes every run.** CI accumulates coverage over time, and each report prints its seed so it can be reproduced.
- **`permissions: contents: read`** follows least privilege for the workflow token.
- The original `python.build.yml` was removed. It only ran on a `master` branch, which this repo doesn't have, and only ran `TEST_PARSING.py`, which the new unit-test job covers.

**Bandit results** ([`logs/bandit_report.txt`](logs/bandit_report.txt)): 18 low-severity issues, none medium or high.
- B603/B607 (2 each): `subprocess` runs `yq` from a partial path. This is a real but minor risk: a malicious `yq` earlier in `PATH` would be executed.
- B404: import of `subprocess`.
- B105 (12): "hard-coded password" on test-file constants such as `'TEST_ARTIFACTS/helm.values.yaml'`. These are **false positives**.
- B311: `random` used in `fuzz.py`. This is intended, since fuzzing doesn't need cryptographic randomness.

---

## 5. Other defects found (by running the project)

| ID | Defect | Status |
|---|---|---|
| BUG-M1 | `main.py` uses `typer` and `Path` without importing them, and calls `main()` instead of `typer.run(main)`. **The tool could not start**, and `TEST_INTEGRATION.py` failed on import. | **Fixed** (commit "Fix two crashes…") |
| BUG-M2 | `show_line_for_paths` prints `key_jsonpath_mapping[key]` *before* the `.get()` check, so a list-index key raises `KeyError: '2'`. **The scan crashed on the project's own `TEST_ARTIFACTS/cap.sys.yaml`.** | **Fixed** (same commit) |
| BUG-M3 | 3 of the 4 original test files can't pass on any machine but the author's: they point at `/Users/arahman/K8S_REPOS/...`. Of 115 scanning tests, 37 error; all 27 graph tests error. | Documented; CI runs the portable `TEST_PARSING.py` |
| BUG-M4 | Undocumented runtime dependency on the external `yq` binary. Without it, 28 more scanning tests fail with `FileNotFoundError: 'yq'`. | Documented in README; CI installs it |
| BUG-M5 | `requirements.txt` is UTF-16 encoded and pins 200+ packages (checkov, boto3, …) the code doesn't use, so `pip install -r` is slow or fails. | Replaced by `requirements-sqa.txt` (6 packages) |
| BUG-M6 | Regexes in `parser.py` use invalid escape sequences (`"\s"`, `"\["`) in normal strings, giving a `SyntaxWarning` on Python 3.12+. These will become errors in a future Python. | Documented |

---

## 6. Lessons learned

1. **Fuzzing finds what the existing tests can't.** The original tests only used well-formed manifests from the author's research corpus. About 30 seconds of fuzzing (5,000 calls) found 7 defects, including two (non-string keys, exponential nesting) that a real repository or an attacker could trigger. The most valuable inputs weren't pure noise. They were *legal* YAML the developers never thought about (`null:` keys, repeated int keys), plus mutations of real files.
2. **Time limits are part of fuzzing.** My first `fuzz.py` had no timeout and simply hung for over 10 minutes on one input. Adding a per-call time limit turned a stuck run into the DoS finding BUG-F2. A fuzzer has to treat "too slow" as a failure, not only "raised an exception".
3. **Group crashes, or the report is useless.** Thousands of crashing runs reduce to 21 signatures and 7 root causes once grouped by exception type and source line. I also had to exclude library frames (`.venv/site-packages`) when picking the line, or the same hang showed up as four "different" bugs inside ruamel.
4. **Defensive type checks are cheap.** The one method with zero crashes (`checkIfValidSecret`) is the one that checks its input type first.
5. **Forensic logging needs a security review too.** The first instinct was to log "what secret was found". That would copy every password into a log file, so the log records only key names and hashes. A security tool's logs must not become a new leak.
6. **Logs reveal performance and accuracy problems.** Counting events in the forensic log exposed that each file is parsed about 26 times, and that some findings silently lose their line number. Neither showed up in the console output.
7. **CI exposes "works on my machine".** Making the project run on a clean GitHub runner surfaced the missing imports, the hard-coded author paths, the hidden `yq` dependency and the broken `requirements.txt`. All of these were invisible on the original developer's computer.
8. **Don't let CI go permanently red.** Reporting fuzz and bandit findings as artifacts and run summaries, instead of failing the build, keeps CI useful for catching new breakage while known bugs are triaged.

---

## 7. Screenshots

Screenshots of the GitHub Actions runs are in [`screenshots/`](screenshots/):

| File | Shows |
|---|---|
| `screenshots/01-actions-runs.png` | Actions tab with the history of SQA CI runs |
| `screenshots/02-run-jobs.png` | One run with all 4 jobs passing |
| `screenshots/03-fuzz-summary.png` | Fuzz report in the run summary |
| `screenshots/04-forensics-summary.png` | Forensics summary (events per method, warnings) |
| `screenshots/05-artifacts.png` | Uploaded artifacts (fuzz-logs, forensics-logs, bandit-report) |
| `screenshots/06-local-fuzz.png` | `python fuzz.py` run locally |
| `screenshots/07-local-forensics-log.png` | `logs/forensics.log` opened locally |

## 8. How to reproduce

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-sqa.txt
brew install yq                      # or: sudo snap install yq
python fuzz.py                       # -> logs/fuzz_report.md, fuzz_crashes.csv, fuzz.log
python main.py TEST_ARTIFACTS        # -> logs/forensics.log
python TEST_PARSING.py               # 23 tests, all pass
bandit -r . -x ./.venv               # static analysis
```
