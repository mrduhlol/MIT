"""Write a reproducible measured report without modifying sandbox state."""
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.detection import Detector


def main():
    training = json.loads((ROOT / 'data/train.json').read_text())
    evaluation = json.loads((ROOT / 'data/evaluation.json').read_text())
    detector = Detector(training)
    report = detector.evaluate(evaluation)
    report['measured_at'] = datetime.now(timezone.utc).isoformat()
    report['training_samples'] = len(training)
    report['limitations'] = [
        'Synthetic fixture holdout shares templates with training; it is a smoke benchmark, not an independent generalization estimate.',
        'The official hidden test set, baseline detector, and published campaign scoring definition have not been supplied.',
        'Model probabilities are uncalibrated. AI authorship and polymorphic malware cannot be proven from these logs.',
        'Per-event latency measures feature extraction and inference only, not network transport or UI polling.',
    ]
    target = ROOT / 'docs/evaluation-results.json'
    target.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
