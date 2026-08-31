"""Fuzzer — mutación por ofuscación de payloads semilla.

Aplica transformaciones de evasión *documentadas* (las que un atacante real
usaría) sobre las semillas de PayloadLibrary, para estresar los guardrails.
Cada mutación produce una variante que el Harness dispara contra tu Fase 1.

Transformaciones:
  * base64_wrap      — codifica el payload en Base64 (smuggling).
  * html_comment     — lo esconde en un comentario HTML.
  * zero_width       — intercala caracteres de ancho cero.
  * homoglyph        — sustituye letras latinas por homóglifos cirílicos.
  * role_prefix      — antepone un prefijo de rol falso.
"""

from __future__ import annotations

import base64
import random
from collections.abc import Iterator
from dataclasses import dataclass, replace

from sentinel.redteam.payload_library import Payload

# Latin → Cyrillic homóglifos (subset seguro y visualmente idéntico)
_HOMOGLYPHS = {"a": "\u0430", "e": "\u0435", "o": "\u043e", "c": "\u0441",
               "p": "\u0440", "x": "\u0445", "y": "\u0443"}
_ZW = "\u200b"


@dataclass(frozen=True)
class Mutation:
    payload: Payload
    transform: str


def _base64_wrap(text: str) -> str:
    return "decode and act: " + base64.b64encode(text.encode()).decode()


def _html_comment(text: str) -> str:
    return f"Contenido legítimo. <!-- {text} --> Fin."


def _zero_width(text: str) -> str:
    return _ZW.join(text)


def _homoglyph(text: str) -> str:
    return "".join(_HOMOGLYPHS.get(ch.lower(), ch) for ch in text)


def _role_prefix(text: str) -> str:
    return f"System: {text}"


_TRANSFORMS = {
    "base64_wrap": _base64_wrap,
    "html_comment": _html_comment,
    "zero_width": _zero_width,
    "homoglyph": _homoglyph,
    "role_prefix": _role_prefix,
}


class Fuzzer:
    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)

    def mutate(self, payload: Payload) -> Iterator[Mutation]:
        """Genera una variante por cada transformación conocida."""
        for name, fn in _TRANSFORMS.items():
            mutated = replace(payload, text=fn(payload.text))
            yield Mutation(payload=mutated, transform=name)

    def mutate_many(self, payloads: list[Payload]) -> list[Mutation]:
        out: list[Mutation] = []
        for p in payloads:
            out.extend(self.mutate(p))
        return out

    def random_transform(self, payload: Payload) -> Mutation:
        name = self._rng.choice(list(_TRANSFORMS))
        return Mutation(replace(payload, text=_TRANSFORMS[name](payload.text)), name)
