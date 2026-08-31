"""ContractAuditor — análisis estático de smart contracts (Slither/Foundry).

Envuelve herramientas estándar (Slither para estático, Foundry para dinámico)
sobre contratos PROPIOS: detecta proxies UUPS mal inicializados, reentrancy,
control de acceso ausente. Interfaz; se cablea a Slither en Fase 2.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ContractFinding:
    detector: str
    severity: str
    description: str


class ContractAuditor:
    def audit(self, contract_path: str) -> list[ContractFinding]:  # pragma: no cover
        """TODO(Fase 2): invocar `slither <path> --json -` y parsear findings."""
        raise NotImplementedError("ContractAuditor.audit pendiente (Fase 2)")
