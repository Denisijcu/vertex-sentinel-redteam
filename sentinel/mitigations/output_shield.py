"""Output Shield — Insecure Output Handling (OWASP LLM02).

Inspecciona lo que el agente PRODUCE antes de que un downstream lo ejecute,
renderice o reenvíe. El principio: la salida de un LLM es entrada no confiable
para el siguiente sistema. Aquí atrapamos:

  * Ejecución arbitraria: shell/eval/exec, `curl | bash`, powershell -enc, rm -rf.
  * Inyección de tool-calls fabricadas en texto libre.
  * Exfiltración: POST a dominios externos, secretos embebidos.
  * Validación de salida estructurada contra un esquema Pydantic estricto.
"""

from __future__ import annotations

import json
import re
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from sentinel.core.policies import (
    Finding,
    LLMRisk,
    RiskAssessment,
    Severity,
)

_DETECTOR = "output_shield"
_M = TypeVar("_M", bound=BaseModel)

_DANGEROUS: tuple[tuple[re.Pattern[str], Severity, str], ...] = (
    (re.compile(r"\brm\s+-rf\s+[/~]", re.I), Severity.CRITICAL, "rm -rf destructivo"),
    (re.compile(r"\b(curl|wget)\b[^\n|]*\|\s*(bash|sh|zsh)\b", re.I), Severity.CRITICAL, "descarga y ejecución (pipe a shell)"),
    (re.compile(r"powershell(\.exe)?\b[^\n]*-e(nc|ncodedcommand)?\b", re.I), Severity.CRITICAL, "PowerShell encoded command"),
    (re.compile(r"\b(os\.system|subprocess\.(Popen|run|call)|eval|exec)\s*\(", re.I), Severity.HIGH, "ejecución dinámica de código"),
    (re.compile(r"\b__import__\s*\(", re.I), Severity.HIGH, "import dinámico ofuscado"),
    (re.compile(r"\b(Invoke-Expression|IEX)\b", re.I), Severity.HIGH, "Invoke-Expression (PowerShell)"),
)

_EXFIL = (
    re.compile(r"\b(fetch|axios|requests\.post|httpx\.post)\b[^\n]*https?://", re.I),
    re.compile(r"\bhttps?://[^\s\"')]+[?&](data|token|secret|key|cookie)=", re.I),
)

_SECRETS = (
    re.compile(r"\b(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})\b"),
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)

_TOOL_INJECTION = re.compile(
    r"<(tool_call|function_call|invoke|antml:invoke)\b", re.I
)


class OutputShield:
    """Evalúa la salida del modelo y opcionalmente valida su esquema."""

    def assess(self, text: str) -> RiskAssessment:
        out = RiskAssessment()
        if not text:
            return out

        for pattern, sev, msg in _DANGEROUS:
            m = pattern.search(text)
            if m:
                out.add(Finding(
                    risk=LLMRisk.LLM02_INSECURE_OUTPUT, severity=sev,
                    detector=_DETECTOR, message=msg, evidence=_snippet(text, m),
                ))

        for pattern in _EXFIL:
            m = pattern.search(text)
            if m:
                out.add(Finding(
                    risk=LLMRisk.LLM06_SENSITIVE_DISCLOSURE, severity=Severity.HIGH,
                    detector=_DETECTOR, message="posible exfiltración a endpoint externo",
                    evidence=_snippet(text, m),
                ))

        for pattern in _SECRETS:
            m = pattern.search(text)
            if m:
                out.add(Finding(
                    risk=LLMRisk.LLM06_SENSITIVE_DISCLOSURE, severity=Severity.CRITICAL,
                    detector=_DETECTOR, message="secreto/credencial embebido en la salida",
                    evidence="[REDACTED]",
                ))

        if _TOOL_INJECTION.search(text):
            out.add(Finding(
                risk=LLMRisk.LLM08_EXCESSIVE_AGENCY, severity=Severity.HIGH,
                detector=_DETECTOR, message="tool-call fabricada dentro de texto de salida",
            ))
        return out

    def validate_schema(self, raw: str | dict, model: type[_M]) -> tuple[_M | None, RiskAssessment]:
        """Fuerza que la salida cumpla un contrato Pydantic estricto.

        Devuelve (instancia|None, assessment). Si no valida, emite un Finding
        LLM02 en vez de dejar pasar JSON malformado o campos inyectados.
        """
        out = RiskAssessment()
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
            instance = model.model_validate(data)
            return instance, out
        except (json.JSONDecodeError, ValidationError, TypeError) as exc:
            out.add(Finding(
                risk=LLMRisk.LLM02_INSECURE_OUTPUT, severity=Severity.MEDIUM,
                detector=_DETECTOR,
                message="la salida no cumple el esquema estructurado esperado",
                evidence=str(exc)[:160],
            ))
            return None, out


def _snippet(text: str, m: re.Match[str], pad: int = 24) -> str:
    a = max(0, m.start() - pad)
    b = min(len(text), m.end() + pad)
    return text[a:b].replace("\n", " ").strip()
