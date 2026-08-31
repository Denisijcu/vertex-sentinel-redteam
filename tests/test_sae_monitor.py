"""Tests del monitor de activaciones (Fase 3).

Se saltan hasta que torch + el SAE estén cableados. La interfaz ya existe, así
que estos tests fijan el contrato esperado para cuando se implemente.
"""

import pytest

pytest.skip("Fase 3: requiere torch + SAE (VSRT_HF_MODEL/VSRT_SAE_RELEASE)",
            allow_module_level=True)


def test_latent_monitor_flags_watched_feature():
    ...  # TODO(Fase 3): activación sintética > umbral -> Finding LLM01
