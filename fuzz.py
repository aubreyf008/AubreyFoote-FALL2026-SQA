'''
fuzz.py -- automated fuzzing of 10 SLI-KUBE methods.

COMP 5710/6710 SQA project, team AubreyFoote (Fall 2026).

Every target method is called many times with random or malformed input.
Any exception it raises is recorded as a crash. Crashes are grouped by
(method, exception type, line that raised it), so each group is one
distinct bug. Results go to:

    logs/fuzz.log          every crash, with the input that caused it
    logs/fuzz_crashes.csv  one row per distinct crash
    logs/fuzz_report.md    readable summary (also printed to the console)

Usage:
    python fuzz.py                       # 500 runs per method, seed 2026
    python fuzz.py --iterations 2000 --seed 7
    python fuzz.py --fail-on-crash       # exit 1 if any crash was found
'''

import argparse
import contextlib
import csv
import io
import logging
import os
import random
import signal
import string
import sys
import tempfile
import time
import traceback

# Keep the forensic log for real scanner runs; fuzzing would flood it.
os.environ.setdefault('SLIKUBE_FORENSICS', '0')

import parser
import scanner
import graphtaint

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(PROJECT_DIR, 'logs')
CORPUS_DIR = os.path.join(PROJECT_DIR, 'TEST_ARTIFACTS')

# YAML shapes that are legal YAML but unusual for a Kubernetes manifest.
ODD_YAML_SNIPPETS = [
    '1.5: float-key\n',
    'null: none-key\n',
    '? [a, b]\n: list-key\n',
    '? {x: 1}\n: map-key\n',
    '1: a\n---\n1: b\n',                      # same int key in two docs
    'apiVersion: v1\nkind: Secret\ndata:\n  password: "{{ .Values.pw }}"\n',
    'a: &anchor {b: 1}\nc: *anchor\n',
    '- - - nested\n',
    '---\n---\n---\n',
    '- []\n---\n- {}\n',
    '!!binary aGVsbG8=\n',
    'key: !custom-tag value\n',
    'a: b: c\n',                              # invalid
    '\t- tab-indented\n',                     # invalid
    '"unterminated\n',                        # invalid
    '{' * 25 + '}' * 25 + '\n',             # deep flow nesting (hang probe)
]

CALL_TIMEOUT_SECONDS = 2.0   # a call slower than this is recorded as a hang


class FuzzTimeout(Exception):
    '''Raised when one call runs longer than CALL_TIMEOUT_SECONDS.'''


def _on_alarm(signum, frame):
    raise FuzzTimeout('call took longer than %.1fs (possible hang / DoS)' % CALL_TIMEOUT_SECONDS)


HAVE_ALARM = hasattr(signal, 'setitimer')   # POSIX only (macOS, Linux CI)

SPECIAL_TOKENS = [': ', '- ', '? ', '---\n', '{{ .Values.x }}', '&a ', '*a', '!!str ',
                  '\t', '\n', '"', "'", '[', ']', '{', '}', '#', '%YAML 1.2\n',
                  'null', '1.5', '\x00', '﻿', 'é', '🔥']


# ---------------------------------------------------------------- generators

def rand_str(rng, max_len=40):
    choice = rng.random()
    if choice < 0.1:
        return ''
    if choice < 0.2:
        return rng.choice(['helm/values.yaml', 'chart/values.yaml', 'deploy/values.yml',
                           '.github/workflows/ci.yml', 'templates/secret.yaml'])
    if choice < 0.3:
        return ''.join(rng.choice(SPECIAL_TOKENS) for _ in range(rng.randint(1, 8)))
    if choice < 0.35:
        return 'A' * rng.randint(1000, 100000)
    if choice < 0.5:
        return ''.join(chr(rng.randint(0, 0x2FFF)) for _ in range(rng.randint(1, max_len)))
    return ''.join(rng.choice(string.printable) for _ in range(rng.randint(1, max_len)))


def rand_scalar(rng):
    return rng.choice([
        lambda: None,
        lambda: rng.choice([True, False]),
        lambda: rng.randint(-2**63, 2**63),
        lambda: rng.choice([0.0, -0.0, float('nan'), float('inf'), rng.random()]),
        lambda: rand_str(rng),
        lambda: rand_str(rng).encode('utf-8', 'ignore'),
    ])()


def rand_value(rng, depth=0):
    '''Random nested Python value: scalars, lists, tuples, dicts.'''
    if depth > 4 or rng.random() < 0.4:
        return rand_scalar(rng)
    kind = rng.random()
    if kind < 0.35:
        return [rand_value(rng, depth + 1) for _ in range(rng.randint(0, 5))]
    if kind < 0.45:
        return tuple(rand_value(rng, depth + 1) for _ in range(rng.randint(0, 5)))
    d = {}
    for _ in range(rng.randint(0, 5)):
        key = rng.choice([rand_str(rng, 10), rng.randint(0, 9), None, 1.5, True, ('t',)])
        d[key] = rand_value(rng, depth + 1)
    return d


def deep_nesting(rng):
    '''Very deeply nested dict/list, to probe recursion limits.'''
    value = 'leaf'
    for i in range(rng.randint(1100, 3000)):
        value = {'k%d' % i: value} if i % 2 else [value]
    return value


def manifest_like(rng):
    '''Dict shaped like a parsed Kubernetes manifest, with random mutations.'''
    d = {
        'apiVersion': 'v1',
        'kind': rng.choice(['Secret', 'ConfigMap', 'Deployment', 'Pod', rand_str(rng, 8)]),
        'metadata': {'name': rand_str(rng, 12), 'namespace': 'default'},
        'data': {
            rng.choice(['username', 'user', 'password', 'pwd', 'token', 'key', 'secret_key']):
                rng.choice([rand_str(rng), 'admin', 'MTIzNAo=', 'BEGIN RSA PRIVATE KEY', None, 42]),
        },
    }
    if rng.random() < 0.5:
        d[rand_scalar(rng) if rng.random() < 0.2 else rand_str(rng, 8)] = rand_value(rng)
    return d


def load_corpus():
    corpus = []
    if os.path.isdir(CORPUS_DIR):
        for name in sorted(os.listdir(CORPUS_DIR)):
            path = os.path.join(CORPUS_DIR, name)
            if os.path.isfile(path) and os.path.getsize(path) < 200000:
                with open(path, 'rb') as f:
                    corpus.append(f.read())
    return corpus or [b'apiVersion: v1\nkind: Pod\n']


def mutate_yaml(rng, corpus):
    '''Bytes of a YAML file: an odd snippet, or a mutated real test manifest.'''
    if rng.random() < 0.3:
        return rng.choice(ODD_YAML_SNIPPETS).encode()
    data = bytearray(rng.choice(corpus))
    for _ in range(rng.randint(1, 6)):
        op = rng.random()
        pos = rng.randint(0, max(len(data) - 1, 0))
        if op < 0.25 and data:
            data[pos] = rng.randint(0, 255)                         # flip a byte
        elif op < 0.45:
            data[pos:pos] = rng.choice(SPECIAL_TOKENS).encode()     # insert a token
        elif op < 0.65:
            data[pos:pos] = rng.choice(ODD_YAML_SNIPPETS).encode()  # insert odd YAML
        elif op < 0.8:
            del data[pos:pos + rng.randint(1, 50)]                  # delete a chunk
        else:
            data = data[:pos]                                       # truncate
    return bytes(data)


# ------------------------------------------------------------------- targets
# Each entry: (name, function, argument generator). The generator returns a
# tuple of positional arguments.

def args_load_multi_yaml(rng, ctx):
    path = os.path.join(ctx['tmp'], 'fuzz_%d.yaml' % rng.randint(0, 10**9))
    with open(path, 'wb') as f:
        f.write(mutate_yaml(rng, ctx['corpus']))
    ctx['files'].append(path)
    return (path,)


def args_single_dict(rng, ctx):
    choice = rng.random()
    if choice < 0.3:
        return ([manifest_like(rng) for _ in range(rng.randint(1, 4))],)
    if choice < 0.5:
        return ([rng.choice([{}, [], None, [{}], {1: 'a'}, {'a': 1}]) for _ in range(rng.randint(1, 4))],)
    return (rand_value(rng),)


def args_key_miner(rng, ctx):
    if rng.random() < 0.15:
        return (deep_nesting(rng), 'leaf')
    tree = manifest_like(rng) if rng.random() < 0.5 else rand_value(rng)
    return (tree, rand_scalar(rng) if rng.random() < 0.5 else 'Secret')


def args_values_recursively(rng, ctx):
    return (deep_nesting(rng) if rng.random() < 0.15 else rand_value(rng),)


def args_json_path_keys(rng, ctx):
    if rng.random() < 0.1:
        return (deep_nesting(rng),)
    return (rng.choice([manifest_like(rng), rand_value(rng), [manifest_like(rng), rand_value(rng)]]),)


def args_valid_helm(rng, ctx):
    return (rand_str(rng) if rng.random() < 0.7 else rand_scalar(rng),)


def args_valid_secret(rng, ctx):
    return (rand_value(rng),)


def args_scan_secrets(rng, ctx):
    if rng.random() < 0.1:
        return (deep_nesting(rng),)
    return (manifest_like(rng) if rng.random() < 0.6 else rand_value(rng),)


def args_item_from_secret(rng, ctx):
    if rng.random() < 0.5:
        d = {rand_str(rng, 8): tuple([rand_str(rng)] for _ in range(3)) for _ in range(rng.randint(0, 3))}
    else:
        d = rand_value(rng)
    return (d, rng.choice([0, 1, 2, 3, -1, 99, None, '0', 1.0]))


def args_helm_string(rng, ctx):
    if rng.random() < 0.5:
        return ((rand_str(rng, 10), rand_str(rng, 10), rand_value(rng)),)
    return (rng.choice([rand_value(rng), (rand_scalar(rng), rand_scalar(rng), None),
                        (1, 'a', 'b'), ('a', 'b'), ()]),)


TARGETS = [
    ('parser.loadMultiYAML',           parser.loadMultiYAML,           args_load_multi_yaml),
    ('parser.getSingleDict4MultiDocs', parser.getSingleDict4MultiDocs, args_single_dict),
    ('parser.keyMiner',                parser.keyMiner,                args_key_miner),
    ('parser.getValuesRecursively',    lambda d: list(parser.getValuesRecursively(d)), args_values_recursively),
    ('parser.find_json_path_keys',     parser.find_json_path_keys,     args_json_path_keys),
    ('parser.checkIfValidHelm',        parser.checkIfValidHelm,        args_valid_helm),
    ('scanner.checkIfValidSecret',     scanner.checkIfValidSecret,     args_valid_secret),
    ('scanner.scanForSecrets',         scanner.scanForSecrets,         args_scan_secrets),
    ('scanner.getItemFromSecret',      scanner.getItemFromSecret,      args_item_from_secret),
    ('graphtaint.constructHelmString', graphtaint.constructHelmString, args_helm_string),
]


# ------------------------------------------------------------------- runner

def short_repr(value, limit=300):
    try:
        text = repr(value)
    except Exception as exc:
        text = '<unreprable %s>' % type(exc).__name__
    return text if len(text) <= limit else text[:limit] + '...(%d chars)' % len(text)


def crash_location(tb):
    '''Deepest stack frame inside this project (not a library), as file:line.'''
    where = 'unknown'
    for frame in traceback.extract_tb(tb):
        in_project = frame.filename.startswith(PROJECT_DIR) and '.venv' not in frame.filename \
            and 'site-packages' not in frame.filename
        if in_project and not frame.filename.endswith('fuzz.py'):
            where = '%s:%d' % (os.path.basename(frame.filename), frame.lineno)
    return where


def input_description(name, args):
    if name == 'parser.loadMultiYAML':
        with open(args[0], 'rb') as f:
            return 'YAML file content: ' + short_repr(f.read())
    return 'args=' + short_repr(args)


def run(iterations, seed):
    os.makedirs(LOG_DIR, exist_ok=True)
    log = logging.getLogger('fuzz')
    log.setLevel(logging.INFO)
    log.handlers.clear()
    handler = logging.FileHandler(os.path.join(LOG_DIR, 'fuzz.log'), mode='w', encoding='utf-8')
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    log.addHandler(handler)
    log.info('fuzzing started seed=%s iterations=%s python=%s', seed, iterations, sys.version.split()[0])

    rng = random.Random(seed)
    ctx = {'corpus': load_corpus(), 'tmp': tempfile.mkdtemp(prefix='slikube_fuzz_'), 'files': []}
    crashes = {}   # (target, exc type, location) -> info dict
    stats = []
    sys.setrecursionlimit(1000)
    if HAVE_ALARM:
        signal.signal(signal.SIGALRM, _on_alarm)

    for name, func, gen in TARGETS:
        n_crash, start = 0, time.time()
        for i in range(iterations):
            args = gen(rng, ctx)
            try:
                # The project prints a lot ("skipping", yq output); keep the console readable.
                with contextlib.redirect_stdout(io.StringIO()):
                    if HAVE_ALARM:
                        signal.setitimer(signal.ITIMER_REAL, CALL_TIMEOUT_SECONDS)
                    try:
                        func(*args)
                    finally:
                        if HAVE_ALARM:
                            signal.setitimer(signal.ITIMER_REAL, 0)
            except Exception as exc:   # RecursionError is a subclass of Exception
                n_crash += 1
                key = (name, type(exc).__name__, crash_location(exc.__traceback__))
                if key not in crashes:
                    crashes[key] = {'count': 0, 'message': short_repr(str(exc), 200),
                                    'input': input_description(name, args), 'iteration': i}
                    log.error('NEW CRASH %s | %s: %s | at %s | %s', name, type(exc).__name__,
                              exc, key[2], crashes[key]['input'])
                crashes[key]['count'] += 1
        for path in ctx['files']:
            os.remove(path)
        ctx['files'].clear()
        seconds = time.time() - start
        stats.append((name, iterations, n_crash, seconds))
        log.info('finished %s runs=%d crashes=%d time=%.2fs', name, iterations, n_crash, seconds)

    os.rmdir(ctx['tmp'])
    write_outputs(stats, crashes, seed, iterations)
    log.info('fuzzing finished distinct_crashes=%d', len(crashes))
    return crashes


def write_outputs(stats, crashes, seed, iterations):
    with open(os.path.join(LOG_DIR, 'fuzz_crashes.csv'), 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['method', 'exception', 'location', 'occurrences', 'message', 'example_input'])
        for (name, exc, where), info in sorted(crashes.items()):
            writer.writerow([name, exc, where, info['count'], info['message'], info['input']])

    lines = ['# Fuzzing report', '',
             'Seed: `%s` | iterations per method: %d | Python %s' % (seed, iterations, sys.version.split()[0]),
             '', '## Summary per method', '',
             '| Method | Runs | Crashing runs | Distinct crashes | Time (s) |',
             '|---|---|---|---|---|']
    for name, runs, n_crash, seconds in stats:
        distinct = sum(1 for k in crashes if k[0] == name)
        lines.append('| `%s` | %d | %d | %d | %.2f |' % (name, runs, n_crash, distinct, seconds))
    lines += ['', '## Distinct crashes', '']
    if not crashes:
        lines.append('No crashes found.')
    for n, ((name, exc, where), info) in enumerate(sorted(crashes.items()), 1):
        lines += ['### %d. `%s` raises `%s` at `%s`' % (n, name, exc, where), '',
                  '- Occurrences: %d' % info['count'],
                  '- Message: `%s`' % info['message'].replace('`', "'"),
                  '- Example input: `%s`' % info['input'].replace('`', "'"), '']
    report = '\n'.join(lines) + '\n'
    with open(os.path.join(LOG_DIR, 'fuzz_report.md'), 'w', encoding='utf-8') as f:
        f.write(report)
    print(report)


def main():
    ap = argparse.ArgumentParser(description='Fuzz 10 SLI-KUBE methods.')
    ap.add_argument('--iterations', type=int, default=500, help='runs per method (default 500)')
    ap.add_argument('--seed', type=int, default=2026, help='random seed, for reproducible runs')
    ap.add_argument('--fail-on-crash', action='store_true', help='exit with code 1 if any crash is found')
    opts = ap.parse_args()
    crashes = run(opts.iterations, opts.seed)
    if opts.fail_on_crash and crashes:
        sys.exit(1)


if __name__ == '__main__':
    main()
