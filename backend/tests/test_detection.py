"""Independent checks of feature extraction and actual holdout measurements."""
import copy
import json
from pathlib import Path

import pytest

from backend.app.detection import Detector, features

DATA = Path(__file__).resolve().parents[2] / 'data'

@pytest.fixture(scope='module')
def detector():
    return Detector(json.loads((DATA/'train.json').read_text()))

@pytest.fixture(scope='module')
def replay():
    return json.loads((DATA/'replay.json').read_text())

def test_ground_truth_and_entity_names_are_not_prediction_inputs(detector, replay):
    event = copy.deepcopy(replay[1])
    expected = detector.predict(event)
    event.update(label=0, identity='different', host='different', id='different')
    assert detector.predict(event) == expected
    del event['label']
    assert detector.predict(event) == expected

def test_clean_activity_and_all_attack_categories(detector, replay):
    assert not detector.predict(replay[0])['suspicious']
    categories = set()
    for event in replay:
        result = detector.predict(event)
        if event['label']:
            assert result['suspicious'], event['id']
            categories.update(e['category'] for e in result['evidence'])
    assert categories == {'phishing', 'credential compromise', 'suspicious behavior', 'prompt injection', 'detection evasion'}

def test_invisible_character_evasion_is_normalized(detector, replay):
    event = next(e for e in replay if e['details'].get('encoded_payload'))
    assert features(event)[0] == 1
    assert features(event)[7] == 1
    assert detector.predict(event)['suspicious']

def test_prompt_injection_remains_untrusted_data(detector, replay):
    event = copy.deepcopy(next(e for e in replay if 'Ignore previous' in e['details'].get('body','')))
    original = copy.deepcopy(event)
    result = detector.predict(event)
    assert event == original
    assert result['suspicious']
    assert any(e['category'] == 'prompt injection' for e in result['evidence'])

def test_metrics_are_computed_from_predictions(detector):
    events = json.loads((DATA/'evaluation.json').read_text())
    result = detector.evaluate(events)
    expected = {'tp':0,'fp':0,'tn':0,'fn':0}
    for event in events:
        prediction = detector.predict(event)['suspicious']
        key = { (True,True):'tp', (True,False):'fp', (False,False):'tn', (False,True):'fn'}[prediction,bool(event['label'])]
        expected[key] += 1
    for key, value in expected.items():
        assert result[key] == value
    assert result['samples'] == len(events) == sum(expected.values())
    assert result['precision'] == pytest.approx(expected['tp']/(expected['tp']+expected['fp']))
    assert result['recall'] == pytest.approx(expected['tp']/(expected['tp']+expected['fn']))
    assert result['f1'] == pytest.approx(2*expected['tp']/(2*expected['tp']+expected['fp']+expected['fn']))
    assert result['false_positive_rate'] == pytest.approx(expected['fp']/(expected['fp']+expected['tn']))
    assert expected['fp'] > 0 and expected['fn'] > 0, 'Benchmark must preserve known blind spots'
    assert result['mean_latency_ms'] > 0
    assert result['p95_latency_ms'] > 0
