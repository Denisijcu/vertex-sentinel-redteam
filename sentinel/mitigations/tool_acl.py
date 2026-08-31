"""Tool ACL — control de agencia por herramienta (OWASP LLM08).

Excessive Agency es que el agente pueda llamar herramientas que no le tocan.
Este módulo aplica listas de control de acceso granulares: qué agente puede
invocar qué tool, con qué parámetros, cuántas veces. Fail-closed por defecto:
lo que no está explícitamente permitido, se niega.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

from sentinel.core.policies import Finding, LLMRisk, Severity

_DETECTOR = "tool_acl"


@dataclass(frozen=True)
class ACLDecision:
    allowed: bool
    finding: Finding | None = None


@dataclass
class ToolRule:
    """Una regla: patrón de tool + restricciones opcionales de parámetros."""

    tool_pattern: str                      # glob: "fs.read", "fs.*", "*"
    max_calls: int | None = None           # None = ilimitado
    denied_params: dict[str, list[str]] = field(default_factory=dict)
    # denied_params: {"path": ["*/etc/*", "*secret*"]} → bloquea esos valores


class ToolACL:
    """Autoriza (agente, tool, params). Fail-closed."""

    def __init__(self, fail_closed: bool = True) -> None:
        self._fail_closed = fail_closed
        self._rules: dict[str, list[ToolRule]] = {}
        self._counts: dict[tuple[str, str], int] = {}

    def allow(self, agent: str, rule: ToolRule) -> "ToolACL":
        self._rules.setdefault(agent, []).append(rule)
        return self

    def _match_rule(self, agent: str, tool: str) -> ToolRule | None:
        for rule in self._rules.get(agent, []):
            if fnmatch.fnmatch(tool, rule.tool_pattern):
                return rule
        # wildcard de agente
        for rule in self._rules.get("*", []):
            if fnmatch.fnmatch(tool, rule.tool_pattern):
                return rule
        return None

    def authorize(
        self, agent: str, tool: str, params: dict | None = None
    ) -> ACLDecision:
        params = params or {}
        rule = self._match_rule(agent, tool)

        if rule is None:
            if self._fail_closed:
                return ACLDecision(False, Finding(
                    risk=LLMRisk.LLM08_EXCESSIVE_AGENCY, severity=Severity.HIGH,
                    detector=_DETECTOR,
                    message=f"agente '{agent}' sin regla para tool '{tool}' (fail-closed)",
                ))
            return ACLDecision(True)

        # límite de llamadas
        if rule.max_calls is not None:
            key = (agent, tool)
            if self._counts.get(key, 0) >= rule.max_calls:
                return ACLDecision(False, Finding(
                    risk=LLMRisk.LLM04_MODEL_DOS, severity=Severity.MEDIUM,
                    detector=_DETECTOR,
                    message=f"'{agent}' excedió max_calls={rule.max_calls} en '{tool}'",
                ))

        # parámetros vetados
        for pname, patterns in rule.denied_params.items():
            value = str(params.get(pname, ""))
            for pat in patterns:
                if fnmatch.fnmatch(value, pat):
                    return ACLDecision(False, Finding(
                        risk=LLMRisk.LLM08_EXCESSIVE_AGENCY, severity=Severity.HIGH,
                        detector=_DETECTOR,
                        message=f"parámetro '{pname}={value}' vetado en '{tool}'",
                        evidence=pat,
                    ))

        # autorizado: contabiliza
        if rule.max_calls is not None:
            key = (agent, tool)
            self._counts[key] = self._counts.get(key, 0) + 1
        return ACLDecision(True)

    def reset_counts(self) -> None:
        self._counts.clear()
