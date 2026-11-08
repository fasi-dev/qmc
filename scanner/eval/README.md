# Scanner evaluation set

`cases.py` is a small, hand-labelled set (22 cases, 32 labelled crypto usages) written separately from the unit-test
corpus. Labels are ground truth: what a reviewer would list, not what the scanner currently emits.

    cd scanner && python -m eval.evaluate          # Markdown table
    cd scanner && python -m eval.evaluate --json

Matching is a multiset match on `(line_start, algorithm)` per case; comment/doc mentions are ignored.

## Results (engine 0.2.0)

| Subset | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| overall | 26 | 0 | 6 | 1.000 | 0.812 | 0.897 |
| excluding known limitations | 26 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| kind = limitation | 0 | 0 | 6 | 1.000 | 0.000 | 0.000 |
| kind = negative | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| kind = realistic | 26 | 0 | 0 | 1.000 | 1.000 | 1.000 |

The same set on the previous `main` (4057826): realistic recall 0.846 (missed: MD5, a Python file with a UTF-8 BOM,
a `createHash` call inside a template-literal interpolation).

## How to read these numbers

* The set is **small and author-written**. Several realistic cases were added *after* the corresponding bugs were
  found, so the before/after comparison is biased in favour of the fixes. Treat 1.000 as "no known regressions on this
  set", not as a measured accuracy on real repositories.
* The six `limitation` cases are real usage the scanner does not resolve (function aliases, `getattr`, algorithm names
  held in constants or config, 3DES). They are kept so the overall recall is not overstated.
* A meaningful accuracy estimate needs labelled samples from real open-source repositories. That is the next step.
