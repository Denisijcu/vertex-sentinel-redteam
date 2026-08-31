"""Validación del fuzzer y la biblioteca de payloads."""

import base64

from sentinel.redteam import Fuzzer, PayloadLibrary
from sentinel.redteam.payload_library import AttackClass


def test_library_has_seeds():
    lib = PayloadLibrary()
    assert len(lib) >= 5
    assert lib.seeds(AttackClass.INSTRUCTION_OVERRIDE)


def test_fuzzer_generates_all_transforms():
    lib = PayloadLibrary()
    fz = Fuzzer(seed=1)
    muts = list(fz.mutate(lib.seeds()[0]))
    transforms = {m.transform for m in muts}
    assert {"base64_wrap", "html_comment", "zero_width", "homoglyph", "role_prefix"} <= transforms


def test_base64_transform_roundtrips():
    lib = PayloadLibrary()
    fz = Fuzzer()
    seed = lib.seeds()[0]
    b64_mut = next(m for m in fz.mutate(seed) if m.transform == "base64_wrap")
    encoded = b64_mut.payload.text.split("act: ", 1)[1]
    assert base64.b64decode(encoded).decode() == seed.text


def test_random_transform_is_deterministic_with_seed():
    lib = PayloadLibrary()
    seed = lib.seeds()[0]
    a = Fuzzer(seed=42).random_transform(seed)
    b = Fuzzer(seed=42).random_transform(seed)
    assert a.transform == b.transform
