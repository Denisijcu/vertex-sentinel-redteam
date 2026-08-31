"""ServiceScanner — descubrimiento de endpoints y microservicios propios.

Enumera servicios expuestos en tu propia infraestructura y revisa higiene
básica (métodos abiertos, headers de seguridad, endpoints de debug). Interfaz;
implementación async con httpx en Fase 2.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ServiceFinding:
    endpoint: str
    issue: str
    severity: str


class ServiceScanner:
    async def scan(self, base_url: str) -> list[ServiceFinding]:  # pragma: no cover
        """TODO(Fase 2): sondear rutas comunes (/docs, /debug, /.env, /actuator),
        revisar headers (HSTS, CSP) y métodos permitidos. Solo infra propia."""
        raise NotImplementedError("ServiceScanner.scan pendiente (Fase 2)")
