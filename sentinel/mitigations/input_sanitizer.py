"""Input Sanitizer — detección de Indirect Prompt Injection (OWASP LLM01).

Filtro heurístico determinista que corre ANTES de que el contenido no confiable
(resultado de una tool, página web, documento, email) llegue al contexto del
agente. No sustituye al Sentinel out-of-band (Fase 2) sino que es la primera
barrera barata: atrapa lo obvio sin gastar un token de LLM.

Principio clave (v0.2): NORMALIZAR y DESANIDAR antes de evaluar. La ofuscación
adversarial no solo añade señal nueva, sino que *destruye* las señales que ya
tenías (ancho cero entre letras, homóglifos, payloads en Base64 o comentarios).
Por eso los detectores de intención corren sobre el texto normalizado, mientras
que la *presencia* de ofuscación se marca sobre el texto original.

Vectores cubiertos:
  * Override de instrucciones / spoofing de autoridad (system/admin/developer).
  * Intención de exfiltración expresada como instrucción inyectada.
  * Smuggling por codificación: Base64 (con desanidado recursivo), comentarios HTML.
  * Unicode adversarial: caracteres de ancho cero, tags invisibles, homóglifos.
  * Exfiltración: imágenes markdown a URLs externas que cargan datos.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

from sentinel.core.policies import (
    Finding,
    LLMRisk,
    RiskAssessment,
    Severity,
)

_DETECTOR = "input_sanitizer"
_MAX_DEPTH = 2  # profundidad de desanidado (base64 dentro de base64, etc.)

# ── Override de instrucciones / spoofing de autoridad ────────────────────
_OVERRIDE_PATTERNS: tuple[tuple[re.Pattern[str], Severity, str], ...] = (
    (re.compile(r"\bignore (all |the |your )?(previous|prior|above|earlier)\b", re.I),
     Severity.HIGH, "intento de anular instrucciones previas"),
    (re.compile(r"\bdisregard (all |the |your )?(previous|prior|above)\b", re.I),
     Severity.HIGH, "intento de descartar instrucciones previas"),
    (re.compile(r"\b(olvida|ignora|descarta)\b.{0,20}\b(instrucciones|anteriores|previas)\b", re.I),
     Severity.HIGH, "override de instrucciones (ES)"),
    (re.compile(r"\byou are now\b|\bfrom now on you\b|\bnew instructions?:\b", re.I),
     Severity.HIGH, "reasignación de rol / nuevas instrucciones"),
    (re.compile(r"\b(system|developer|admin)\s*(prompt|mode|message|role)\b", re.I),
     Severity.MEDIUM, "referencia a rol privilegiado (posible spoofing)"),
    (re.compile(r"^\s*(system|assistant|developer)\s*:", re.I | re.M),
     Severity.MEDIUM, "prefijo de rol inyectado en contenido de datos"),
    (re.compile(r"\b(reveal|print|repeat|show).{0,20}(system prompt|instructions|rules)\b", re.I),
     Severity.HIGH, "intento de extracción de system prompt (LLM06)"),
)

# Intención de exfiltración expresada como instrucción (verbos fuertes + objeto
# sensible). Curado a bajo falso-positivo: no incluye verbos genéricos como
# "send" ni objetos genéricos como "data".
_EXFIL_INTENT = re.compile(
    r"\b(exfiltrate|leak|steal|dump|smuggle)\b.{0,40}"
    r"\b(secret|password|credential|token|api[ _-]?key|private[ _-]?key|cookie)s?\b",
    re.I,
)

# ── Smuggling por codificación ───────────────────────────────────────────
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
_MD_HIDDEN = re.compile(r"\[[^\]]*\]:\s*#", re.M)  # ref-link markdown oculto
_B64_BLOB = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])")

# ── Unicode adversarial ──────────────────────────────────────────────────
_ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}
_TAG_BLOCK = re.compile(r"[\U000E0000-\U000E007F]")  # Unicode "tags" invisibles

# Homóglifos cross-script → Latin. Curado (Cirílico/Griego lookalikes comunes).
# Nunca toca Latin acentuado legítimo (á, é, ñ...).
_CONFUSABLES = {
    # Cirílico minúsculas
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0441": "c", "\u0440": "p",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0455": "s", "\u04bb": "h",
    "\u043a": "k", "\u043c": "m", "\u0442": "t", "\u0432": "v", "\u043d": "n",
    # Cirílico mayúsculas
    "\u0410": "A", "\u0415": "E", "\u041e": "O", "\u0421": "C", "\u0420": "P",
    "\u0425": "X", "\u0423": "Y", "\u041a": "K", "\u041c": "M", "\u0422": "T",
    "\u0412": "B", "\u041d": "H",
    # Griego
    "\u03bf": "o", "\u039f": "O", "\u03b1": "a", "\u03c1": "p", "\u03bd": "v",
    "\u03b5": "e", "\u03c4": "t", "\u03c5": "u",
}

# ── Exfiltración ─────────────────────────────────────────────────────────
_MD_IMAGE_EXFIL = re.compile(
    r"!\[[^\]]*\]\((https?://[^)]+[?&][^)]*=[^)]+)\)", re.I
)


def _normalize(text: str) -> str:
    """Neutraliza ofuscación para que los detectores vean el payload real.

    1) Quita caracteres invisibles (ancho cero, tags).
    2) Elimina marcadores de comentario HTML (deja el contenido inline).
    3) Mapea homóglifos cross-script a Latin.
    4) Normalización de compatibilidad Unicode (fullwidth, ligaduras).
    """
    cleaned = "".join(ch for ch in text if ch not in _ZERO_WIDTH)
    cleaned = _TAG_BLOCK.sub("", cleaned)
    cleaned = cleaned.replace("<!--", " ").replace("-->", " ")
    cleaned = "".join(_CONFUSABLES.get(ch, ch) for ch in cleaned)
    return unicodedata.normalize("NFKC", cleaned)


class InputSanitizer:
    """Evalúa contenido no confiable y devuelve un `RiskAssessment`."""

    def assess(self, text: str, _depth: int = 0) -> RiskAssessment:
        assessment = RiskAssessment()
        if not text:
            return assessment

        normalized = _normalize(text)

        # Intención: sobre texto NORMALIZADO (recupera señales que la ofuscación mató).
        self._check_overrides(normalized, assessment)
        self._check_exfil_intent(normalized, assessment)
        self._check_exfiltration(normalized, assessment)

        # Presencia de ofuscación + desanidado: sobre texto ORIGINAL.
        self._check_encoding_smuggling(text, assessment, _depth)
        self._check_unicode(text, assessment)
        return assessment

    # -- detectores ------------------------------------------------------
    def _check_overrides(self, text: str, out: RiskAssessment) -> None:
        for pattern, sev, msg in _OVERRIDE_PATTERNS:
            m = pattern.search(text)
            if m:
                out.add(Finding(
                    risk=LLMRisk.LLM01_PROMPT_INJECTION,
                    severity=sev,
                    detector=_DETECTOR,
                    message=msg,
                    evidence=_snippet(text, m.start(), m.end()),
                ))

    def _check_exfil_intent(self, text: str, out: RiskAssessment) -> None:
        m = _EXFIL_INTENT.search(text)
        if m:
            out.add(Finding(
                risk=LLMRisk.LLM01_PROMPT_INJECTION, severity=Severity.HIGH,
                detector=_DETECTOR,
                message="instrucción inyectada de exfiltración de secretos",
                evidence=_snippet(text, m.start(), m.end()),
            ))

    def _check_encoding_smuggling(
        self, text: str, out: RiskAssessment, depth: int
    ) -> None:
        for m in _HTML_COMMENT.finditer(text):
            out.add(Finding(
                risk=LLMRisk.LLM01_PROMPT_INJECTION, severity=Severity.MEDIUM,
                detector=_DETECTOR, message="comentario HTML oculto en datos",
                evidence=_snippet(text, m.start(), m.end()),
            ))
        if _MD_HIDDEN.search(text):
            out.add(Finding(
                risk=LLMRisk.LLM01_PROMPT_INJECTION, severity=Severity.LOW,
                detector=_DETECTOR, message="referencia markdown oculta",
            ))
        for m in _B64_BLOB.finditer(text):
            decoded = _try_b64(m.group(0))
            if not decoded:
                continue
            # Desanidar: correr el detector completo sobre el contenido decodificado.
            inner = self.assess(decoded, _depth=depth + 1) if depth < _MAX_DEPTH else RiskAssessment()
            if inner.findings:
                out.add(Finding(
                    risk=LLMRisk.LLM01_PROMPT_INJECTION, severity=Severity.MEDIUM,
                    detector=_DETECTOR,
                    message="payload Base64 decodifica a contenido malicioso",
                    evidence=decoded[:120],
                ))
                out.findings.extend(inner.findings)
            else:
                out.add(Finding(
                    risk=LLMRisk.LLM01_PROMPT_INJECTION, severity=Severity.LOW,
                    detector=_DETECTOR, message="blob Base64 decodificable en datos",
                    evidence=m.group(0)[:60],
                ))

    def _check_unicode(self, text: str, out: RiskAssessment) -> None:
        if any(ch in _ZERO_WIDTH for ch in text):
            out.add(Finding(
                risk=LLMRisk.LLM01_PROMPT_INJECTION, severity=Severity.MEDIUM,
                detector=_DETECTOR, message="caracteres de ancho cero (smuggling)",
            ))
        if _TAG_BLOCK.search(text):
            out.add(Finding(
                risk=LLMRisk.LLM01_PROMPT_INJECTION, severity=Severity.HIGH,
                detector=_DETECTOR, message="Unicode 'tags' invisibles (payload oculto)",
            ))
        if _has_homoglyph_mix(text):
            out.add(Finding(
                risk=LLMRisk.LLM01_PROMPT_INJECTION, severity=Severity.MEDIUM,
                detector=_DETECTOR, message="mezcla de scripts (homóglifos, posible evasión)",
            ))

    def _check_exfiltration(self, text: str, out: RiskAssessment) -> None:
        m = _MD_IMAGE_EXFIL.search(text)
        if m:
            out.add(Finding(
                risk=LLMRisk.LLM06_SENSITIVE_DISCLOSURE, severity=Severity.HIGH,
                detector=_DETECTOR,
                message="imagen markdown con URL externa parametrizada (canal de exfiltración)",
                evidence=_snippet(text, m.start(), m.end()),
            ))


# ── helpers ──────────────────────────────────────────────────────────────
def _snippet(text: str, start: int, end: int, pad: int = 24) -> str:
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    return text[a:b].replace("\n", " ").strip()


def _try_b64(blob: str) -> str | None:
    try:
        raw = base64.b64decode(blob, validate=True)
        decoded = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    printable = sum(c.isprintable() or c.isspace() for c in decoded)
    if not decoded or printable / len(decoded) < 0.85:
        return None
    return decoded


def _has_homoglyph_mix(text: str) -> bool:
    """Detecta palabras que mezclan Latin con Cyrillic/Greek (típico de evasión)."""
    for word in re.findall(r"\w{4,}", text):
        scripts = set()
        for ch in word:
            if not ch.isalpha():
                continue
            try:
                name = unicodedata.name(ch)
            except ValueError:
                continue
            if "CYRILLIC" in name:
                scripts.add("cyrillic")
            elif "GREEK" in name:
                scripts.add("greek")
            elif "LATIN" in name:
                scripts.add("latin")
        if "latin" in scripts and (scripts & {"cyrillic", "greek"}):
            return True
    return False
