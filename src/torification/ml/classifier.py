"""ML block classifier — train on JSONL events, predict blocked vs ok."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from torification.ml.features import BlockFeatures


class BlockClassifier:
    """Wrapper around sklearn RandomForest; falls back to heuristics if no model."""

    def __init__(self, model_path: str | Path | None = None) -> None:
        self.model_path = Path(model_path).expanduser() if model_path else None
        self._model: Any = None
        if self.model_path and self.model_path.is_file():
            self._load()

    def _load(self) -> None:
        import joblib

        self._model = joblib.load(self.model_path)

    def predict_blocked(self, features: BlockFeatures, threshold: float = 0.75) -> tuple[bool, float]:
        if self._model is None:
            # heuristic fallback until model is trained
            blocked = bool(features.direct_failed and features.socks_ok)
            conf = 0.9 if blocked else 0.5
            if features.state_onehot_timeout or features.state_onehot_refused:
                blocked = True
                conf = 0.85
            return blocked, conf

        vec = [features.to_vector()]
        proba = self._model.predict_proba(vec)[0]
        # classes: ['blocked', 'ok'] alphabetically
        classes = list(self._model.classes_)
        blocked_idx = classes.index("blocked") if "blocked" in classes else 0
        p = float(proba[blocked_idx])
        return p >= threshold, p

    def train_from_jsonl(self, jsonl_path: str | Path, out_path: str | Path) -> dict[str, float]:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import cross_val_score
        import joblib
        import numpy as np

        X, y = [], []
        for line in Path(jsonl_path).expanduser().read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            fd = row["features"]
            bf = BlockFeatures(**{k: fd[k] for k in BlockFeatures.__dataclass_fields__})
            X.append(bf.to_vector())
            y.append(row["label"])

        if len(X) < 20:
            raise ValueError(f"Need at least 20 training samples, got {len(X)}")

        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        scores = cross_val_score(clf, np.array(X), np.array(y), cv=min(5, len(X) // 4))
        clf.fit(X, y)
        out = Path(out_path).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(clf, out)
        self._model = clf
        self.model_path = out
        return {"cv_mean": float(scores.mean()), "cv_std": float(scores.std()), "n_samples": len(X)}
