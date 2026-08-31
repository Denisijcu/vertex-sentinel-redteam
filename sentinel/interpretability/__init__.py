"""Auditoría mecanicista con Sparse Autoencoders (Fase 3).

Interfaces definidas; la implementación real depende de torch + el modelo/SAE
que configures (VSRT_HF_MODEL, VSRT_SAE_RELEASE). Se deja fuera del install base
para no obligar a bajar torch en el harness defensivo.
"""

from sentinel.interpretability.hook_manager import HookManager
from sentinel.interpretability.sae_encoder import SAEEncoder
from sentinel.interpretability.latent_monitor import LatentMonitor

__all__ = ["HookManager", "SAEEncoder", "LatentMonitor"]
