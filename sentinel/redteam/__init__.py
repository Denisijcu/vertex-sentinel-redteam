"""Red team automatizado (auto-testeo).

Este subsistema NO genera ataques nuevos contra modelos de terceros: toma
técnicas de inyección públicas y documentadas (taxonomía OWASP LLM), las muta
con transformaciones de ofuscación conocidas, y mide si TUS propios guardrails
(mitigations/) las atrapan. El producto útil es la lista de payloads que se te
colaron → los huecos que hay que tapar.
"""

from sentinel.redteam.payload_library import PayloadLibrary, AttackClass, Payload
from sentinel.redteam.fuzzer import Fuzzer
from sentinel.redteam.prompt_injector import RedTeamHarness, HarnessReport

__all__ = [
    "PayloadLibrary", "AttackClass", "Payload",
    "Fuzzer", "RedTeamHarness", "HarnessReport",
]
