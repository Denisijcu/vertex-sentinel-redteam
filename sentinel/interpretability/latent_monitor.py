"""LatentMonitor — sentinel de activaciones sospechosas en tiempo real.

Vigila features del SAE asociadas a intención maliciosa / engaño latente
(sleeper agents) / exfiltración, y emite un Finding cuando superan umbral.

La idea: mapear un puñado de feature-ids a conceptos de riesgo y alertar si se
activan por encima de baseline durante la inferencia. Implementación en Fase 3;
firma pensada para integrarse con el mismo RiskAssessment que la Fase 1.
"""

from __future__ import annotations

from typing import Any

from sentinel.core.policies import RiskAssessment


class LatentMonitor:
    def __init__(self, watched_features: dict[int, str], threshold: float = 0.5) -> None:
        # watched_features: {feature_id: etiqueta_de_riesgo}
        self.watched_features = watched_features
        self.threshold = threshold

    def inspect(self, sae_features: Any) -> RiskAssessment:  # pragma: no cover
        """Revisa features vigiladas y devuelve un RiskAssessment.

        TODO(Fase 3): para cada feature vigilada, si su activación media supera
        el umbral, emitir un Finding (LLM01/LLM06 según la etiqueta).
        """
        raise NotImplementedError("LatentMonitor.inspect pendiente (Fase 3)")
