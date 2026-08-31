"""Blue-vs-red: el harness mide cuánto atrapan los guardrails."""

from sentinel.redteam import RedTeamHarness


def test_harness_runs_and_reports():
    report = RedTeamHarness(threshold=0.65).run(include_mutations=True)
    assert report.total > 0
    assert 0.0 <= report.catch_rate <= 1.0


def test_seeds_are_all_caught():
    """Las semillas documentadas deben atraparse TODAS tras la normalización."""
    report = RedTeamHarness(threshold=0.65).run(include_mutations=False)
    assert report.catch_rate == 1.0, report.summary()


def test_mutations_catch_rate_floor():
    """Tras el _normalize()+desanidado, las mutaciones de ofuscación no deben
    bajar de 90%. Si baja, alguien introdujo una regresión en el sanitizer."""
    report = RedTeamHarness(threshold=0.65).run(include_mutations=True)
    assert report.catch_rate >= 0.9, report.summary()


def test_evasions_are_reported_as_gaps():
    report = RedTeamHarness(threshold=0.65).run(include_mutations=True)
    for ev in report.evasions:
        assert ev.transform  # cada evasión dice qué transformación la logró
