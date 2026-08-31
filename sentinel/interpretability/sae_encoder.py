"""SAEEncoder — proyecta activaciones a features dispersas.

Carga un Sparse Autoencoder preentrenado (p.ej. Gemma Scope) y descompone el
residual stream en features monosemánticas interpretables.

Implementación diferida a Fase 3.
"""

from __future__ import annotations

from typing import Any


class SAEEncoder:
    def __init__(self, release: str, layer: int) -> None:
        self.release = release
        self.layer = layer

    def encode(self, activations: Any) -> Any:  # pragma: no cover
        """activations [seq, d_model] -> features dispersas [seq, d_sae].

        TODO(Fase 3): cargar SAE del release, aplicar encoder, devolver
        activaciones de features (mayormente cero) para inspección.
        """
        raise NotImplementedError("SAEEncoder.encode pendiente (Fase 3)")
