"""Optional AI helper for passive security triage.

This module is intentionally lightweight and uses free or low-cost model providers
when an API key is configured. It is not required for the core project to operate.

The idea is simple:
- summarize a finding in plain language
- prioritize remediation
- create an executive summary from risk data

This is only a support layer and must never replace evidence-based CVE data.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


class FreeAIHelper:
    """Call a free public LLM endpoint when configured.

    This keeps the project compatible with free providers such as OpenRouter or a
    similar endpoint that accepts OpenAI-compatible requests. If no API key is
    configured, the helper returns a local summary instead of failing.
    """

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None, model: str = "openai/gpt-oss-20b"):
        self.api_key = api_key or os.environ.get("FREE_AI_API_KEY")
        self.base_url = base_url or os.environ.get("FREE_AI_BASE_URL", "https://openrouter.ai/api/v1")
        self.model = model or os.environ.get("FREE_AI_MODEL", "openai/gpt-oss-20b")

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def summarize_risk(self, asset: Dict[str, Any]) -> str:
        """Create a plain-English explanation for a single asset."""
        if not self.is_configured():
            return self._fallback_summary(asset)

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a cyber security assistant. Summarize the risk in clear French or English. "
                        "Never invent facts. Only use the evidence provided."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(asset, ensure_ascii=False, indent=2),
                },
            ],
            "temperature": 0.2,
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://localhost",
            "X-Title": "P-ASM Passive Risk Assistant",
        }

        req = Request(
            f"{self.base_url}/chat/completions",
            method="POST",
            headers=headers,
            data=json.dumps(payload).encode("utf-8"),
        )

        try:
            with urlopen(req, timeout=20) as response:
                data = json.loads(response.read().decode("utf-8"))
                msg = data.get("choices", [{}])[0].get("message", {}).get("content")
                if msg:
                    return msg.strip()
        except (URLError, HTTPError, ValueError, TimeoutError, OSError):
            pass

        return self._fallback_summary(asset)

    def _fallback_summary(self, asset: Dict[str, Any]) -> str:
        name = asset.get("subdomain", "unknown")
        risk_label = asset.get("risk_label", "inconnu")
        score = asset.get("score", 0)
        category = asset.get("category", "Autres")
        notes = asset.get("notes", "")
        return (
            f"{name} est classé {risk_label} avec un score de {score}. "
            f"Catégorie : {category}. "
            f"Éléments de risque observés : {notes or 'Aucun signal détaillé disponible.'}"
        )


def build_ai_summary(asset: Dict[str, Any]) -> str:
    """Convenience function used by the app if AI is enabled.

    The environment variable FREE_AI_API_KEY can be populated by the user, but the
    project stays fully usable without it.
    """
    helper = FreeAIHelper()
    return helper.summarize_risk(asset)


def build_local_summary(asset: Dict[str, Any]) -> str:
    """Return the safe local explanation without calling an external provider."""
    return FreeAIHelper()._fallback_summary(asset)
