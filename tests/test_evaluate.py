from pathlib import Path
import yaml
from netanalyzer.evaluate import ratio

def test_ratio_formats_percentage():
    assert ratio(3, 3) == "100% (3/3)"
    assert ratio(1, 2) == "50% (1/2)"

def test_ratio_handles_zero_denominator():
    assert ratio(0, 0) == "n/a"

def test_labels_file_is_valid():
    labels = yaml.safe_load(Path("data/labels.yml").read_text())["captures"]
    assert len(labels) >= 7
    for item in labels:
        assert {"file", "description", "attack", "expected"} <= set(item)
        assert isinstance(item["attack"], bool)
        assert isinstance(item["expected"], list)