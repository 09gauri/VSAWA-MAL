import os
import requests

LM_STUDIO_BASE_URL = os.environ.get(
    "LM_STUDIO_BASE_URL",
    "http://host.docker.internal:1234/v1"
)
LM_STUDIO_MODEL = os.environ.get("LM_STUDIO_MODEL", "qwen2.5-3b-instruct")

# max_tokens default raised from 180 -> 1024.
#
# The previous 180-token ceiling was cutting answers off mid-sentence -- a
# typical "explain this vulnerability and what should I do" reply needs at
# least 400-600 tokens, and detailed remediation walkthroughs need more. 1024
# is still inside the comfort zone of even a 4k-context local model so it
# won't blow up on slow hardware, but it gives the model enough room to finish
# its thought instead of stopping at a punctuation boundary.
#
# Operators on very small models can override with the LM_STUDIO_MAX_TOKENS
# env var.
DEFAULT_MAX_TOKENS = int(os.environ.get("LM_STUDIO_MAX_TOKENS", "1024"))


def chat_with_lmstudio(messages, temperature=0.2, max_tokens=None):
    """
    Talk to a local LM Studio (or any OpenAI-compatible) chat completion
    endpoint and return the assistant's text reply.

    `max_tokens` defaults to DEFAULT_MAX_TOKENS so callers don't accidentally
    re-introduce the old 180-token truncation by forgetting to set it.
    """
    if max_tokens is None:
        max_tokens = DEFAULT_MAX_TOKENS

    url = f"{LM_STUDIO_BASE_URL}/chat/completions"

    payload = {
        "model": LM_STUDIO_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        # Asking the server to NOT stream lets us read the whole reply from a
        # single JSON response. Streaming would require a different code path
        # in chat_service / the Flask endpoint -- not worth it for a chat box.
        "stream": False,
    }

    response = requests.post(url, json=payload, timeout=300)
    response.raise_for_status()
    data = response.json()

    # Defensive: if the server returned no choices, surface something the user
    # can act on rather than blowing up with a KeyError.
    choices = data.get("choices") or []
    if not choices:
        return "(The local LM returned no content. Check that LM Studio is running and a model is loaded.)"

    content = (choices[0].get("message") or {}).get("content") or ""
    return content.strip()