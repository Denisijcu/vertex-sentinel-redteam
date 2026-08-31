"""Red Team Harness — mide la cobertura de tus guardrails (blue vs red).

Corre semillas + mutaciones contra tu InputSanitizer y reporta:
  * catch rate (qué % de payloads fueron marcados ROJO).
  * la lista de EVASIONES: payloads que se colaron → tus huecos reales.

Por diseño el objetivo por defecto es TU PROPIO guardrail local, no un modelo
externo. `probe_target()` existe para auditar un endpoint de agente propio
(Oracle Core, Kontia MCP…) que configures en .env; no lo apuntes a terceros.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.core.policies import Verdict
from sentinel.mitigations import InputSanitizer
from sentinel.redteam.fuzzer import Fuzzer
from sentinel.redteam.payload_library import PayloadLibrary


@dataclass
class EvasionCase:
    text: str
    transform: str
    score: float
    note: str


@dataclass
class HarnessReport:
    total: int = 0
    caught: int = 0
    evasions: list[EvasionCase] = field(default_factory=list)

    @property
    def catch_rate(self) -> float:
        return round(self.caught / self.total, 4) if self.total else 0.0

    def summary(self) -> str:
        return (f"catch_rate={self.catch_rate:.1%}  "
                f"({self.caught}/{self.total})  evasiones={len(self.evasions)}")


class RedTeamHarness:
    def __init__(self, threshold: float = 0.65) -> None:
        self._sanitizer = InputSanitizer()
        self._threshold = threshold
        self._lib = PayloadLibrary()
        self._fuzzer = Fuzzer(seed=1337)

    def run(self, include_mutations: bool = True) -> HarnessReport:
        report = HarnessReport()
        seeds = self._lib.seeds()

        for p in seeds:
            self._evaluate(p.text, "seed", p.note, report)

        if include_mutations:
            for mut in self._fuzzer.mutate_many(seeds):
                self._evaluate(mut.payload.text, mut.transform,
                               mut.payload.note, report)
        return report

    def _evaluate(self, text: str, transform: str, note: str,
                  report: HarnessReport) -> None:
        report.total += 1
        assessment = self._sanitizer.assess(text)
        if assessment.verdict(self._threshold) is Verdict.RED:
            report.caught += 1
        else:
            report.evasions.append(EvasionCase(
                text=text[:100], transform=transform,
                score=assessment.score, note=note,
            ))

    # -- auditoría de endpoint PROPIO (opcional) -------------------------
    async def probe_target(self, base_url: str, api_key: str = "") -> HarnessReport:
        """Dispara payloads contra un endpoint de agente propio y revisa si su
        RESPUESTA muestra señales de haber obedecido la inyección.

        TODO(Fase 2): implementar el cliente httpx async + análisis de respuesta
        con el OutputShield. Requiere que definas el contrato del target
        (VSRT_TARGET_BASE_URL). Se deja como interfaz para no acoplar el harness
        a un esquema de API todavía indefinido.
        """
        raise NotImplementedError(
            "probe_target: define primero el contrato del endpoint propio en .env"
        )
