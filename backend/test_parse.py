# backend/test_parse.py
from backend.ingestions.log_ingest import LogIngestor
from backend.features.log_features import LogFeatureExtractor
from backend.detection.rules.ssh_rules import SSHRuleDetector
from backend.detection.ml.train import MLTrainer
from backend.detection.ml.predict import MLPredictor
from backend.detection.ml.hybrid_engine import HybridDecisionEngine
from backend.evaluation.metrics import Evaluator

ingestor = LogIngestor()
extractor = LogFeatureExtractor()
rule_detector = SSHRuleDetector()
trainer = MLTrainer()
hybrid = HybridDecisionEngine()
evaluator = Evaluator()

print("Ingesting logs...")
events = ingestor.ingest_file("datasets/raw/logs/ssh_auth_large.log")
print("Raw events parsed:", len(events))

features = extractor.extract(events)
print("Feature rows generated:", len(features))
print("Sample features (first 5):", features[:5])

print("Running rule-based detection...")
rule_alerts = rule_detector.detect(features)
print("Rule alerts:", len(rule_alerts))

print("Training ML models...")
# safety: trainer.train should check for empty features/classes
trainer.train(features)

print("Running ML detection...")
ml_results = MLPredictor().predict(features)
print("ML results:", len(ml_results))

print("\nFinal Hybrid Alerts:")
final_alerts = hybrid.decide(rule_alerts, ml_results)

for fa in final_alerts:
    print(fa)

# Optional: quick evaluation print (requires features, rule_alerts, ml_results, final_alerts)
try:
    y_true = [1 if f["label"] == "attack" else 0 for f in features]
    y_rule = [1 if f["ip"] in [a["ip"] for a in rule_alerts] else 0 for f in features]
    # ML-based predictions (majority vote)
    y_ml = []
    for r in ml_results:
        votes = list(r["ml_prediction"].values())
        y_ml.append(1 if votes.count("attack") >= 1 else 0)
    y_hybrid = [1 if f["ip"] in [a["ip"] for a in final_alerts] else 0 for f in features]

    print("\nEvaluation Results:")
    print("Rule-based IDS:", evaluator.evaluate(y_true, y_rule))
    print("ML-based IDS:", evaluator.evaluate(y_true, y_ml))
    print("Hybrid IDS:", evaluator.evaluate(y_true, y_hybrid))
except Exception:
    pass
