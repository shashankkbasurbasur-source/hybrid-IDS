# backend/evaluation/reports.py

"""
Evaluation report generator — prints and saves classification summaries.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from sklearn.metrics import classification_report, confusion_matrix
from backend.core.logger import get_logger

logger       = get_logger(__name__)
RESULTS_DIR  = Path(__file__).resolve().parent.parent.parent / "results"


def generate_report(y_true: list, y_pred: list, model_name: str) -> dict:
    report_text = classification_report(y_true, y_pred, target_names=["Normal", "Attack"])
    cm          = confusion_matrix(y_true, y_pred).tolist()

    report = {
        "model"      : model_name,
        "timestamp"  : datetime.now(timezone.utc).isoformat(),
        "report"     : report_text,
        "confusion_matrix": cm,
    }

    RESULTS_DIR.mkdir(exist_ok=True)
    out_path = RESULTS_DIR / f"{model_name.lower().replace(' ', '_')}_report.json"
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)

    logger.info("Report saved: %s", out_path)
    print(f"\n=== {model_name} ===\n{report_text}")
    return report