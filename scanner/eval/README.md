# Scanner evaluation set

`cases.py` is a small, hand-labelled set (22 cases, 32 labelled crypto usages) written separately from the unit-test
corpus. Labels are ground truth: what a reviewer would list, not what the scanner currently emits.

    cd scanner && python -m eval.evaluate          # Markdown table
    cd scanner && python -m eval.evaluate --json

Matching is a multiset match on `(line_start, algorithm)` per case; comment/doc mentions are ignored.

## Results (engine 0.3.0)

| Subset | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| overall | 29 | 0 | 3 | 1.000 | 0.906 | 0.951 |
| excluding known limitations | 29 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| kind = limitation | 0 | 0 | 3 | 1.000 | 0.000 | 0.000 |
| kind = negative | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| kind = realistic | 29 | 0 | 0 | 1.000 | 1.000 | 1.000 |

History on this set: `main` @ 4057826 (engine 0.1.0) realistic recall 0.846 (missed MD5, a UTF-8 BOM file, a
template-literal call). Engine 0.2.0: overall recall 0.812 (6 limitation misses). Engine 0.3.0 resolves simple
Python aliases and detects 3DES/DES/RC4/Blowfish, so three former limitation cases were re-labelled `fixed-*`
(kind `realistic`); the remaining misses are `getattr`, an algorithm held in a Java constant, and one held in a JS
config object.

## How to read these numbers

* The set is **small and author-written**. Several realistic cases were added *after* the corresponding bugs were
  found, so the before/after comparison is biased in favour of the fixes. Treat 1.000 as "no known regressions on this
  set", not as a measured accuracy on real repositories.
* The `limitation` cases are real usage the scanner does not resolve (`getattr`, algorithm names held in constants or
  config). They are kept so the overall recall is not overstated. The `fixed-*` cases were written before the fixes
  but the fixes were designed with them in view, so they are not independent evidence either.
* A meaningful accuracy estimate needs labelled samples from real open-source repositories. That is the next step.
