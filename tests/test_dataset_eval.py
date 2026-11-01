"""
test_dataset_eval.py

WHAT: pins the file-level evaluation maths - confusion counts, derived metrics, AUC, and
      that threshold tuning maximises F1.

WHY : these functions produce the headline numbers in dataset_results.md. A silent off-by-one
      in the confusion matrix or a wrong AUC would misrepresent how well the detector works,
      so the arithmetic is tested on tiny hand-checkable inputs.
"""

from __future__ import annotations

from evaluation import dataset_eval as de


def _s(label, score):
    return de.Scored(path="p", label=label, source_type="T", variant="v", split="test",
                     entropy=float(score), score=score)


def test_confusion_and_metrics_counts():
    # scores: positives 80,60 ; negatives 10,40 ; threshold 50 -> TP=2? no: 60>=50 yes,80 yes;
    # negatives 10<50,40<50 -> TN=2, FP=0, FN=0
    data = [_s(1, 80), _s(1, 60), _s(0, 10), _s(0, 40)]
    tp, fp, tn, fn = de.confusion(data, 50)
    assert (tp, fp, tn, fn) == (2, 0, 2, 0)
    m = de.metrics(tp, fp, tn, fn)
    assert m["precision"] == 1.0 and m["recall"] == 1.0 and m["f1"] == 1.0 and m["fpr"] == 0.0


def test_metrics_with_false_positive():
    tp, fp, tn, fn = de.confusion([_s(1, 80), _s(0, 70), _s(0, 10)], 50)
    assert (tp, fp, tn, fn) == (1, 1, 1, 0)
    m = de.metrics(tp, fp, tn, fn)
    assert round(m["precision"], 3) == 0.5 and m["recall"] == 1.0 and m["fpr"] == 0.5


def test_auc_is_one_for_perfectly_separable_scores():
    data = [_s(1, 90), _s(1, 80), _s(0, 20), _s(0, 10)]
    _, _, auc = de.roc_auc(data)
    assert auc == 1.0


def test_auc_is_half_for_random_scores():
    # identical score distributions for both classes -> AUC 0.5
    data = [_s(1, 50), _s(0, 50), _s(1, 50), _s(0, 50)]
    _, _, auc = de.roc_auc(data)
    assert auc == 0.5


def test_tune_threshold_prefers_best_f1():
    # a threshold of 50 cleanly separates; the tuner should pick a value that does so.
    data = [_s(1, 80), _s(1, 60), _s(0, 40), _s(0, 10)]
    t = de.tune_threshold(data)
    tp, fp, tn, fn = de.confusion(data, t)
    assert de.metrics(tp, fp, tn, fn)["f1"] == 1.0
