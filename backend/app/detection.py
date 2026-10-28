"""Small, explainable Bernoulli naive Bayes classifier. No remote services."""
import math
import re
import statistics
import time
import unicodedata

FEATURES = ['credential_lure', 'sender_mismatch', 'auth_anomaly', 'mfa_fatigue',
            'beacon', 'transfer', 'prompt_override', 'obfuscation']

def features(event):
    d = event['details']
    raw = str(d.get('body', ''))
    text = unicodedata.normalize('NFKC', raw).lower()
    text = re.sub(r'[\u200b-\u200f\ufeff]', '', text)
    return [
        int(event['source'] == 'email' and any(s in text for s in ['verify your account', 'confirm your password', 'sign in immediately', 'validate your credentials'])),
        int(event['source'] == 'email' and d.get('sender_domain') != d.get('claimed_domain')),
        int(event['source'] == 'auth' and d.get('new_device', False) and d.get('travel_kmh', 0) > 900),
        int(event['source'] == 'auth' and d.get('mfa_denials', 0) >= 5),
        int(event['source'] == 'network' and d.get('periodic', False) and d.get('rare_destination', False)),
        int(event['source'] == 'network' and d.get('bytes_out', 0) > 50_000_000 and d.get('rare_destination', False)),
        int(any(s in text for s in ['ignore previous instructions', 'ignore all previous', 'override system', 'disable detection', 'mark this event as safe'])),
        int(raw != text and bool(re.search(r'[\u200b-\u200f\ufeff]', raw)) or d.get('encoded_payload', False)),
    ]

REASONS = [
    ('phishing', 'Email asks the recipient to verify credentials under urgency. AI authorship cannot be inferred from writing style.'),
    ('phishing', 'Sender domain differs from the organization the message claims to represent.'),
    ('credential compromise', 'A new device appears with travel velocity above 900 km/h; this may indicate stolen credentials.'),
    ('credential compromise', 'At least five denied MFA prompts suggest approval fatigue.'),
    ('suspicious behavior', 'Periodic traffic to a rare destination resembles command-and-control beaconing.'),
    ('suspicious behavior', 'More than 50 MB was sent to a rare destination; investigate possible exfiltration.'),
    ('prompt injection', 'Untrusted content attempts to override instructions or suppress detection. It is treated only as data.'),
    ('detection evasion', 'Invisible characters or a simulated encoded payload may conceal a malicious instruction.'),
]

class Detector:
    def __init__(self, training):
        groups = {label: [features(e) for e in training if e['label'] == label] for label in (0, 1)}
        self.prior = {k: (len(v)+1)/(len(training)+2) for k,v in groups.items()}
        self.probs = {k: [(sum(row[i] for row in v)+1)/(len(v)+2) for i in range(len(FEATURES))] for k,v in groups.items()}

    def predict(self, event):
        vector = features(event)
        scores = {k: math.log(self.prior[k]) + sum(math.log(p if x else 1-p) for x,p in zip(vector, probs)) for k,probs in self.probs.items()}
        probability = 1/(1+math.exp(scores[0]-scores[1]))
        evidence = [{'feature': FEATURES[i], 'category': REASONS[i][0], 'explanation': REASONS[i][1]} for i,x in enumerate(vector) if x]
        return {'suspicious': probability >= .5, 'confidence': round(probability, 4), 'evidence': evidence}

    def evaluate(self, events):
        counts = {'tp':0, 'fp':0, 'tn':0, 'fn':0}
        latencies = []
        for event in events:
            start = time.perf_counter_ns()
            result = self.predict(event)
            latencies.append((time.perf_counter_ns()-start)/1_000_000)
            counts[('t' if result['suspicious'] == bool(event['label']) else 'f') + ('p' if result['suspicious'] else 'n')] += 1
        tp,fp,tn,fn = (counts[k] for k in ['tp','fp','tn','fn'])
        precision = tp/(tp+fp) if tp+fp else 0
        recall = tp/(tp+fn) if tp+fn else 0
        return {**counts, 'precision': precision, 'recall': recall, 'f1': 2*precision*recall/(precision+recall) if precision+recall else 0,
                'false_positive_rate': fp/(fp+tn) if fp+tn else 0, 'mean_latency_ms': statistics.mean(latencies),
                'p95_latency_ms': sorted(latencies)[math.ceil(len(latencies)*.95)-1], 'samples': len(events),
                'dataset': 'held-out-synthetic-v1', 'model': 'Bernoulli naive Bayes v1',
                'scope': 'Per-event classifier wall-clock latency; synthetic holdout, not production accuracy. Uncalibrated model probabilities.'}
