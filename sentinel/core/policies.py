"""Catálogo de políticas OWASP LLM Top 10 y modelos de resultado compartidos.

`policies.py` es la fuente de verdad taxonómica: cada guardrail de
`mitigations/` y cada payload de `redteam/` se etiqueta contra uno de estos
`LLMRisk`, de modo que un hallazgo defensivo y un ataque ofensivo hablan el
mismo idioma y se pueden correlacionar en los reportes.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class LLMRisk(str, Enum):
    """OWASP Top 10 for LLM Applications (edición 2025)."""

    LLM01_PROMPT_INJECTION = "LLM01"
    LLM02_INSECURE_OUTPUT = "LLM02"
    LLM03_DATA_POISONING = "LLM03"
    LLM04_MODEL_DOS = "LLM04"
    LLM05_SUPPLY_CHAIN = "LLM05"
    LLM06_SENSITIVE_DISCLOSURE = "LLM06"
    LLM07_INSECURE_PLUGIN = "LLM07"
    LLM08_EXCESSIVE_AGENCY = "LLM08"
    LLM09_OVERRELIANCE = "LLM09"
    LLM10_MODEL_THEFT = "LLM10"


class Severity(str, Enum):
    """Severidad de un hallazgo. Ordenable vía `WEIGHT`."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 0.05,
    Severity.LOW: 0.25,
    Severity.MEDIUM: 0.5,
    Severity.HIGH: 0.8,
    Severity.CRITICAL: 1.0,
}


class Verdict(str, Enum):
    """Semáforo del gateway (alineado con tu convención SOC)."""

    GREEN = "green"    # limpio
    YELLOW = "yellow"  # sospechoso
    RED = "red"        # comprometido / bloqueado


class Finding(BaseModel):
    """Un hallazgo individual producido por un guardrail o detector."""

    risk: LLMRisk
    severity: Severity
    detector: str = Field(..., description="Nombre del detector que lo emitió")
    message: str
    evidence: str = Field("", description="Fragmento que disparó la detección")

    @property
    def weight(self) -> float:
        return SEVERITY_WEIGHT[self.severity]


class RiskAssessment(BaseModel):
    """Resultado agregado de evaluar un input o un output."""

    findings: list[Finding] = Field(default_factory=list)

    @property
    def score(self) -> float:
        """Riesgo agregado en [0, 1]. Combinación probabilística (no suma
        lineal) para que múltiples señales medias escalen sin saturar de golpe.
        """
        residual = 1.0
        for f in self.findings:
            residual *= (1.0 - f.weight)
        return round(1.0 - residual, 4)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(self.findings, key=lambda f: f.weight).severity

    def verdict(self, threshold: float) -> Verdict:
        s = self.score
        if s >= threshold:
            return Verdict.RED
        if s >= threshold * 0.5:
            return Verdict.YELLOW
        return Verdict.GREEN

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)


# ── Metadatos legibles del catálogo (para reportes / CLI) ────────────────
POLICY_CATALOG: dict[LLMRisk, str] = {
    LLMRisk.LLM01_PROMPT_INJECTION: "Prompt Injection (directa e indirecta)",
    LLMRisk.LLM02_INSECURE_OUTPUT: "Insecure Output Handling",
    LLMRisk.LLM03_DATA_POISONING: "Training Data / Memory Poisoning",
    LLMRisk.LLM04_MODEL_DOS: "Model Denial of Service",
    LLMRisk.LLM05_SUPPLY_CHAIN: "Supply Chain Vulnerabilities",
    LLMRisk.LLM06_SENSITIVE_DISCLOSURE: "Sensitive Information Disclosure",
    LLMRisk.LLM07_INSECURE_PLUGIN: "Insecure Plugin / Tool Design",
    LLMRisk.LLM08_EXCESSIVE_AGENCY: "Excessive Agency",
    LLMRisk.LLM09_OVERRELIANCE: "Overreliance",
    LLMRisk.LLM10_MODEL_THEFT: "Model Theft",
}
