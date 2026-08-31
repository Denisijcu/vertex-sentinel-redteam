"""Pruebas de propiedad (Hypothesis) — invariantes del sanitizer.

Las pruebas de ejemplo (test_normalization) fijan casos concretos. Estas fijan
INVARIANTES sobre un espacio grande de entradas generadas, para atrapar huecos
que no anticipamos: payloads envueltos en texto arbitrario, o transformaciones
compuestas. Complementan al harness, no lo reemplazan.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from sentinel.core.policies import Verdict
from sentinel.mitigations import InputSanitizer
from sentinel.redteam.fuzzer import Fuzzer, _TRANSFORMS
from sentinel.redteam.payload_library import PayloadLibrary

san = InputSanitizer()
T = 0.65

_SEEDS = [p.text for p in PayloadLibrary().seeds()]
_TRANSFORM_NAMES = list(_TRANSFORMS)

# Texto "portador" benigno: letras/espacios/puntuación suave. No contiene
# términos de ataque, así que por sí solo nunca debe dar ROJO.
_benign = st.text(alphabet="abcdefghijklmnopqrstuvwxyz ,.-", max_size=80)


# ── INVARIANTE 1: un payload conocido no se esconde envolviéndolo en texto ──
@given(pre=_benign, suf=_benign, payload=st.sampled_from(_SEEDS))
@settings(max_examples=250)
def test_prop_payload_survives_benign_wrapping(pre, suf, payload):
    """Indirect injection real = payload enterrado en un documento benigno.
    Envolverlo no debe bajar el veredicto de ROJO."""
    text = f"{pre} {payload} {suf}"
    assert san.assess(text).verdict(T) is Verdict.RED


# ── INVARIANTE 2: una transformación del fuzzer sobre una semilla → ROJO ─────
@given(seed_idx=st.integers(0, len(_SEEDS) - 1),
       transform=st.sampled_from(_TRANSFORM_NAMES))
@settings(max_examples=150)
def test_prop_single_transform_stays_red(seed_idx, transform):
    """Cualquier ofuscación individual conocida debe seguir siendo atrapada.
    Si agregas un transform nuevo al fuzzer y no endureces el sanitizer,
    este test lo caza."""
    payload = PayloadLibrary().seeds()[seed_idx]
    mutated = _TRANSFORMS[transform](payload.text)
    assert san.assess(mutated).verdict(T) is Verdict.RED


# ── INVARIANTE 3: texto benigno no dispara ROJO (control de falsos positivos) ─
@given(txt=st.text(alphabet="abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789 ,.-áéíóúñ",
                   min_size=1, max_size=120))
@settings(max_examples=250)
def test_prop_benign_text_not_red(txt):
    """Ningún texto ordinario (incl. acentos español) debe caer en ROJO."""
    assert san.assess(txt).verdict(T) is not Verdict.RED
