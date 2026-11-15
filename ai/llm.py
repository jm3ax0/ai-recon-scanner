"""
llm.py - OPTIONAL: ask Claude (a large language model) to write the summary.

Only runs when the environment variable ANTHROPIC_API_KEY is set.
If anything goes wrong (no key, no internet, refusal, error) we return None
and the caller falls back to the offline summary - the tool always works.

Privacy note: when enabled, a compact list of findings (titles, URLs,
evidence) is sent to the Anthropic API. Leave the key unset to stay offline.
"""
import json
import logging

import config

log = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a friendly security educator reviewing an automated scan of the user's OWN "
    "practice lab (authorized testing). Write a short report for a beginner: "
    "1) a 2-3 sentence overall assessment, 2) the top priorities in order with a one-line "
    "reason each, 3) concrete defensive fixes. Focus on remediation and understanding. "
    "Do not include exploit code or attack payloads. Use plain language and short bullet points."
)


def llm_summary(target: str, ports: list[dict], findings: list[dict], language: str = "en") -> str | None:
    if not config.ANTHROPIC_API_KEY:
        return None
    try:
        import anthropic
    except ImportError:
        log.warning("ANTHROPIC_API_KEY is set but the 'anthropic' package is not installed.")
        return None

    compact = {
        "target": target,
        "open_ports": [{"port": p["port"], "service": p["service"], "version": p["version"]} for p in ports],
        "findings": [{k: f.get(k) for k in ("priority", "severity", "score", "title", "location",
                                            "parameter", "evidence")} for f in findings[:25]],
    }
    lang_note = "Write the report in Arabic." if language == "ar" else "Write the report in English."
    user_msg = f"{lang_note}\n\nScan results (JSON):\n{json.dumps(compact, indent=1)}"

    client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY, timeout=120.0)
    request = dict(model=config.LLM_MODEL, max_tokens=4000, system=SYSTEM_PROMPT,
                   messages=[{"role": "user", "content": user_msg}])
    try:
        try:
            # Server-side fallback: if the model declines, the API retries on a suitable model.
            response = client.beta.messages.create(
                **request, betas=["server-side-fallback-2026-07-01"], fallbacks="default")
        except TypeError:
            # Older SDK without the `fallbacks` argument -> plain request.
            response = client.messages.create(**request)
    except anthropic.AuthenticationError:
        log.error("LLM: invalid ANTHROPIC_API_KEY - using offline summary.")
        return None
    except anthropic.RateLimitError:
        log.error("LLM: rate limited - using offline summary.")
        return None
    except anthropic.APIStatusError as exc:
        log.error("LLM: API error %s - using offline summary.", exc.status_code)
        return None
    except anthropic.APIConnectionError:
        log.error("LLM: could not reach the API - using offline summary.")
        return None

    if response.stop_reason == "refusal":
        log.warning("LLM declined to summarize - using offline summary.")
        return None
    text = "".join(block.text for block in response.content if block.type == "text").strip()
    return text or None
