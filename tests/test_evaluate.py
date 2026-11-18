from netanalyzer.evaluate import ratio

def test_ratio_formats_percentage():
    assert ratio(3, 3) == "100% (3/3)"
    assert ratio(1, 2) == "50% (1/2)"

def test_ratio_handles_zero_denominator():
    assert ratio(0, 0) == "n/a"