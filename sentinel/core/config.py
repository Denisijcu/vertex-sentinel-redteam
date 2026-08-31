"""Configuración global de V-SRT.

Carga desde variables de entorno / .env con Pydantic Settings.
Todos los umbrales y modos de fallo viven aquí para que las capas
defensivas (mitigations) y ofensivas (redteam) lean una sola fuente de verdad.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class FailMode(str, Enum):
    """Comportamiento del gateway ante una evaluación no concluyente."""

    CLOSED = "closed"  # ante la duda, bloquea (recomendado en prod)
    OPEN = "open"      # deja pasar pero loguea (útil en desarrollo)


class Settings(BaseSettings):
    """Configuración tipada de todo el runtime del Sentinel."""

    model_config = SettingsConfigDict(
        env_prefix="VSRT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ---- Umbrales de riesgo ----
    risk_threshold_input: float = Field(0.65, ge=0.0, le=1.0)
    risk_threshold_output: float = Field(0.70, ge=0.0, le=1.0)
    fail_mode: FailMode = FailMode.CLOSED

    # ---- Sentinel out-of-band ----
    sentinel_provider: str = "anthropic"
    sentinel_model: str = "claude-sonnet-4-6"

    # ---- Target bajo prueba (Fase 2) ----
    target_base_url: str = "http://localhost:8000"
    target_api_key: str = ""

    # ---- Interpretabilidad (Fase 3) ----
    hf_model: str = "google/gemma-2-2b"
    sae_release: str = "gemma-scope-2b-pt-res"
    sae_layer: int = 12

    # ---- Logging ----
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    """Settings cacheados (una sola lectura de entorno por proceso)."""
    return Settings()
