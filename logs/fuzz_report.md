# Fuzzing report

Seed: `2026` | iterations per method: 500 | Python 3.13.9

## Summary per method

| Method | Runs | Crashing runs | Distinct crashes | Time (s) |
|---|---|---|---|---|
| `parser.loadMultiYAML` | 500 | 45 | 2 | 27.22 |
| `parser.getSingleDict4MultiDocs` | 500 | 119 | 3 | 0.03 |
| `parser.keyMiner` | 500 | 76 | 2 | 0.41 |
| `parser.getValuesRecursively` | 500 | 87 | 2 | 0.41 |
| `parser.find_json_path_keys` | 500 | 203 | 2 | 1.58 |
| `parser.checkIfValidHelm` | 500 | 94 | 1 | 0.01 |
| `scanner.checkIfValidSecret` | 500 | 0 | 0 | 0.02 |
| `scanner.scanForSecrets` | 500 | 13 | 1 | 0.58 |
| `scanner.getItemFromSecret` | 500 | 345 | 5 | 0.02 |
| `graphtaint.constructHelmString` | 500 | 234 | 3 | 0.03 |

## Distinct crashes

### 1. `graphtaint.constructHelmString` raises `TypeError` at `graphtaint.py:25`

- Occurrences: 9
- Message: `'cannot unpack non-iterable int object'`
- Example input: `args=(-8211937972886103715,)`

### 2. `graphtaint.constructHelmString` raises `TypeError` at `graphtaint.py:27`

- Occurrences: 103
- Message: `'can only concatenate str (not "bytes") to str'`
- Example input: `args=((b"(Rw[i3 +^R_+hR+$fS<I|oVg'HGIICd%-p'?a_\x0c!", None, None),)`

### 3. `graphtaint.constructHelmString` raises `ValueError` at `graphtaint.py:25`

- Occurrences: 122
- Message: `'not enough values to unpack (expected 3, got 0)'`
- Example input: `args=((),)`

### 4. `parser.checkIfValidHelm` raises `TypeError` at `parser.py:135`

- Occurrences: 94
- Message: `"a bytes-like object is required, not 'str'"`
- Example input: `args=(b'\x0c3#EoyA4xm<',)`

### 5. `parser.find_json_path_keys` raises `RecursionError` at `parser.py:256`

- Occurrences: 56
- Message: `'maximum recursion depth exceeded'`
- Example input: `args=({'k2637': [{'k2635': [{'k2633': [{'k2631': [{'k2629': [{'k2627': [{'k2625': [{'k2623': [{'k2621': [{'k2619': [{'k2617': [{'k2615': [{'k2613': [{'k2611': [{'k2609': [{'k2607': [{'k2605': [{'k2603': [{'k2601': [{'k2599': [{'k2597': [{'k2595': [{'k2593': [{'k2591': [{'k2589': [{'k2587': [{'k2585': [{'...(16601 chars)`

### 6. `parser.find_json_path_keys` raises `TypeError` at `parser.py:272`

- Occurrences: 147
- Message: `"expected string or bytes-like object, got 'NoneType'"`
- Example input: `args=([{'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'h)I\x0b3=js{G|'', 'namespace': 'default'}, 'data': {'password': 'MTIzNAo='}}, [-7801572243591569457, ['.github/workflows/ci.yml', [b'9a?)\r'[qm.rU^\tE78qHKW', {None: 1234753280437299859, True: {4: False, 8: 5354245811732169211}, 1.5: 'de...(463 chars)`

### 7. `parser.getSingleDict4MultiDocs` raises `IndexError` at `parser.py:401`

- Occurrences: 36
- Message: `'list index out of range'`
- Example input: `args=([{}, [], [], {}],)`

### 8. `parser.getSingleDict4MultiDocs` raises `TypeError` at `parser.py:391`

- Occurrences: 65
- Message: `"'NoneType' object is not iterable"`
- Example input: `args=(None,)`

### 9. `parser.getSingleDict4MultiDocs` raises `TypeError` at `parser.py:424`

- Occurrences: 18
- Message: `"unsupported operand type(s) for +: 'NoneType' and 'str'"`
- Example input: `args=([{None: -0.0, ('t',): None, 6: {1.5: None, True: {1.5: b'lQq=T\\W|%$FgCQ){NUKoqD'S U[,{28'}, ']1.5}1.5': {5: {'2\\[': inf, 'ಟ⸬❗ⷐ⨺ᤪ⎖Ⴈ': None, '1.5\x00#': True}}, ('t',): [['', '"\ufeff\'"---\n', None], {1.5: None, 'A6': '1.5? }\t- *a🔥', True: 6309376126024951722, 2: 441488043456680078}, (-1335920703...(1855 chars)`

### 10. `parser.getValuesRecursively` raises `RecursionError` at `parser.py:85`

- Occurrences: 43
- Message: `'maximum recursion depth exceeded'`
- Example input: `args=([{'k1883': [{'k1881': [{'k1879': [{'k1877': [{'k1875': [{'k1873': [{'k1871': [{'k1869': [{'k1867': [{'k1865': [{'k1863': [{'k1861': [{'k1859': [{'k1857': [{'k1855': [{'k1853': [{'k1851': [{'k1849': [{'k1847': [{'k1845': [{'k1843': [{'k1841': [{'k1839': [{'k1837': [{'k1835': [{'k1833': [{'k1831': [{...(11702 chars)`

### 11. `parser.getValuesRecursively` raises `RecursionError` at `parser.py:89`

- Occurrences: 44
- Message: `'maximum recursion depth exceeded'`
- Example input: `args=({'k2393': [{'k2391': [{'k2389': [{'k2387': [{'k2385': [{'k2383': [{'k2381': [{'k2379': [{'k2377': [{'k2375': [{'k2373': [{'k2371': [{'k2369': [{'k2367': [{'k2365': [{'k2363': [{'k2361': [{'k2359': [{'k2357': [{'k2355': [{'k2353': [{'k2351': [{'k2349': [{'k2347': [{'k2345': [{'k2343': [{'k2341': [{'...(15015 chars)`

### 12. `parser.keyMiner` raises `RecursionError` at `parser.py:46`

- Occurrences: 40
- Message: `'maximum recursion depth exceeded'`
- Example input: `args=({'k1809': [{'k1807': [{'k1805': [{'k1803': [{'k1801': [{'k1799': [{'k1797': [{'k1795': [{'k1793': [{'k1791': [{'k1789': [{'k1787': [{'k1785': [{'k1783': [{'k1781': [{'k1779': [{'k1777': [{'k1775': [{'k1773': [{'k1771': [{'k1769': [{'k1767': [{'k1765': [{'k1763': [{'k1761': [{'k1759': [{'k1757': [{'...(11226 chars)`

### 13. `parser.keyMiner` raises `RecursionError` at `parser.py:52`

- Occurrences: 36
- Message: `'maximum recursion depth exceeded'`
- Example input: `args=([{'k2981': [{'k2979': [{'k2977': [{'k2975': [{'k2973': [{'k2971': [{'k2969': [{'k2967': [{'k2965': [{'k2963': [{'k2961': [{'k2959': [{'k2957': [{'k2955': [{'k2953': [{'k2951': [{'k2949': [{'k2947': [{'k2945': [{'k2943': [{'k2941': [{'k2939': [{'k2937': [{'k2935': [{'k2933': [{'k2931': [{'k2929': [{...(18846 chars)`

### 14. `parser.loadMultiYAML` raises `FuzzTimeout` at `parser.py:179`

- Occurrences: 13
- Message: `'call took longer than 2.0s (possible hang / DoS)'`
- Example input: `YAML file content: b'{{{{{{{{{{{{{{{{{{{{{{{{{}}}}}}}}}}}}}}}}}}}}}}}}}\n'`

### 15. `parser.loadMultiYAML` raises `TypeError` at `parser.py:272`

- Occurrences: 32
- Message: `"expected string or bytes-like object, got 'CommentedKeyMap'"`
- Example input: `YAML file content: b'? {x: 1}\n: map-key\n'`

### 16. `scanner.getItemFromSecret` raises `AttributeError` at `scanner.py:238`

- Occurrences: 172
- Message: `"'bytes' object has no attribute 'items'"`
- Example input: `args=(b'', 2)`

### 17. `scanner.getItemFromSecret` raises `IndexError` at `scanner.py:239`

- Occurrences: 47
- Message: `'tuple index out of range'`
- Example input: `args=({'A\x0b': (["T;8H+EEwp4'"], [''IM_R"gI3kYP9.2zFvJYI{.p'], ["$w3/RiCQ'Vp"])}, 99)`

### 18. `scanner.getItemFromSecret` raises `KeyError` at `scanner.py:239`

- Occurrences: 23
- Message: `'1.0'`
- Example input: `args=({'"yS': {'deploy/values.yml': []}}, 1.0)`

### 19. `scanner.getItemFromSecret` raises `TypeError` at `scanner.py:239`

- Occurrences: 98
- Message: `"string indices must be integers, not 'NoneType'"`
- Example input: `args=({('t',): 'ᆶξ', 9: True, None: {2: (), ('t',): False}, 2: {None: b"\n]\x00: '", '': {None: [{('t',): 0.10810941748586811, True: True}, b'', 0.9669391809782679, inf, True], True: 0.0, 1.5: ({('t',): '', True: b'+!t(l\x0c=zt^uS'%'}, {}, {}), 'o7\n.T': inf}}}, None)`

### 20. `scanner.getItemFromSecret` raises `TypeError` at `scanner.py:240`

- Occurrences: 5
- Message: `"'int' object is not iterable"`
- Example input: `args=({None: [0.0, {' ': {1.5: 3145706924513665840}, ('t',): {'': True, 1.5: {'chart/values.yaml': 0.38325147540637594, 4: None}}}, 'templates/secret.yaml', 1112569317709823981], 1.5: [b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...(39158 chars)`

### 21. `scanner.scanForSecrets` raises `RecursionError` at `parser.py:64`

- Occurrences: 13
- Message: `'maximum recursion depth exceeded'`
- Example input: `args=({'k2583': [{'k2581': [{'k2579': [{'k2577': [{'k2575': [{'k2573': [{'k2571': [{'k2569': [{'k2567': [{'k2565': [{'k2563': [{'k2561': [{'k2559': [{'k2557': [{'k2555': [{'k2553': [{'k2551': [{'k2549': [{'k2547': [{'k2545': [{'k2543': [{'k2541': [{'k2539': [{'k2537': [{'k2535': [{'k2533': [{'k2531': [{'...(16250 chars)`

