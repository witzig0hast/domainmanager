"""Ollama client: turns deterministic findings into a German summary with prioritized fixes."""
from __future__ import annotations

import json

import httpx

from .config import settings

SCHEMA = {
    "type": "object",
    "properties": {
        "zusammenfassung": {"type": "string"},
        "risiko": {"type": "string", "enum": ["niedrig", "mittel", "hoch", "kritisch"]},
        "massnahmen": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "prioritaet": {"type": "integer"},
                    "titel": {"type": "string"},
                    "betrifft": {"type": "string"},
                    "schritte": {"type": "string"},
                },
                "required": ["prioritaet", "titel", "betrifft", "schritte"],
            },
        },
    },
    "required": ["zusammenfassung", "risiko", "massnahmen"],
}

SYSTEM = (
    "Du bist ein nüchterner IT-Sicherheitsberater für ein Homelab. Du bekommst die Ergebnisse "
    "automatisierter Prüfungen einer Domain bei Cloudflare als JSON. Regeln:\n"
    "- Verwende AUSSCHLIESSLICH die gelieferten Befunde. Erfinde keine Hosts, Ports oder Schwachstellen.\n"
    "- Antworte auf Deutsch, knapp und konkret.\n"
    "- 'massnahmen': höchstens 8, sortiert nach Wichtigkeit (1 = zuerst). Fasse gleichartige Befunde "
    "mehrerer Hosts zusammen. 'schritte' beschreibt konkret, wo man im Cloudflare-Dashboard oder am Server klickt/ändert.\n"
    "- 'risiko' richtet sich nach dem schwersten Befund.\n"
    "- Befunde mit severity 'ok' oder 'info' brauchen keine Maßnahme."
)


class OllamaError(Exception):
    pass


async def models() -> list[dict]:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{settings.ollama_url}/api/tags")
            r.raise_for_status()
            data = r.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OllamaError(f"Ollama nicht erreichbar ({exc.__class__.__name__})") from exc
    out = []
    for m in data.get("models") or []:
        size_gb = round((m.get("size") or 0) / 1e9, 1)
        details = m.get("details") or {}
        is_embed = "embed" in m.get("name", "") or details.get("family") in ("nomic-bert", "bert")
        out.append({
            "name": m.get("name"),
            "size_gb": size_gb,
            "params": details.get("parameter_size"),
            "quant": details.get("quantization_level"),
            "usable": not is_embed and size_gb <= settings.ollama_max_model_gb,
        })
    return sorted(out, key=lambda m: m["size_gb"])


async def analyze(scan: dict, model: str) -> dict:
    relevant = [
        {k: f[k] for k in ("host", "severity", "title", "detail")}
        for f in scan["findings"] if f["severity"] not in ("ok", "info")
    ][:80]
    payload = {
        "gepruefte_hosts": scan["hosts"],
        "anzahl_nach_schwere": scan["counts"],
        "score_0_bis_100": scan["score"],
        "befunde": relevant,
    }
    body = {
        "model": model,
        "stream": False,
        "format": SCHEMA,
        "keep_alive": settings.ollama_keep_alive,
        "options": {"temperature": 0.1, "num_ctx": settings.ollama_num_ctx},
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ],
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=5.0)) as client:
            r = await client.post(f"{settings.ollama_url}/api/chat", json=body)
            r.raise_for_status()
            data = r.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OllamaError(f"Ollama-Anfrage fehlgeschlagen ({exc.__class__.__name__})") from exc
    content = (data.get("message") or {}).get("content", "")
    try:
        result = json.loads(content)
    except ValueError as exc:
        raise OllamaError("Modell lieferte kein gültiges JSON – größeres Modell wählen.") from exc
    result["massnahmen"] = sorted(result.get("massnahmen") or [], key=lambda m: m.get("prioritaet", 99))[:8]
    result["model"] = model
    result["eval_seconds"] = round((data.get("total_duration") or 0) / 1e9, 1)
    return result
