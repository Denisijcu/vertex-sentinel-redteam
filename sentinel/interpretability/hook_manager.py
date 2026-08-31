"""HookManager — extrae activaciones del residual stream.

Engancha capas intermedias del transformador (vía TransformerLens o hooks
nativos de PyTorch) y captura el residual stream para la capa objetivo.

Implementación diferida a Fase 3: requiere torch + el modelo. Firma estable
para que sae_encoder y latent_monitor programen contra ella desde ya.
"""

from __future__ import annotations

from typing import Any


class HookManager:
    def __init__(self, model_name: str, layer: int) -> None:
        self.model_name = model_name
        self.layer = layer

    def capture(self, prompt: str) -> Any:  # -> torch.Tensor  # pragma: no cover
        """Devuelve las activaciones residuales [seq, d_model] de `layer`.

        TODO(Fase 3): cargar modelo, registrar forward hook en
        blocks.{layer}.hook_resid_post, correr forward, devolver tensor.
        """
        raise NotImplementedError("HookManager.capture pendiente (Fase 3)")
