"""Turn an enriched vulnerability record into a structured, grounded alert (Gemini)."""
import json
import time
from enum import Enum

from google import genai
from google.genai import errors, types
from pydantic import BaseModel, Field

SYSTEM_PROMPT = """You are a vulnerability analyst writing alerts for security teams.

Rules:
- Use ONLY the source material provided. Do not add facts from memory.
- Never invent patch versions, KB numbers, registry keys, config settings, or IOCs.
  If the sources do not state a fixed version, say the vendor advisory must be
  checked, and point to the advisory link if one is provided.
- If no workaround is stated in the sources, say none was provided.
- Detection ideas may be general (which logs to review, what behavior to look for),
  but label them as general guidance, not vendor-confirmed.
- Be concise and direct. No marketing language or filler."""


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Alert(BaseModel):
    tldr: str = Field(description="1-2 plain-English sentences a manager would understand.")
    technical_summary: str = Field(description="2-4 sentences for engineers: vuln type, attack vector, impact.")
    affected: str = Field(description="Affected products/versions as stated in the sources.")
    severity: Severity
    fix: str = Field(description="Patch or upgrade guidance, only as stated in the sources.")
    mitigations: list[str] = Field(description="Workarounds or interim mitigations from the sources.")
    detection: list[str] = Field(description="Detection/hunting ideas; mark general guidance as such.")
    gaps: str = Field(description="What the sources did NOT say that a defender would want to know.")


def make_client(api_key):
    return genai.Client(api_key=api_key)


def summarize(item, client, model, retries=3):
    """Ask Gemini for a structured alert. Returns a plain dict."""
    material = json.dumps(item, indent=2)
    config = types.GenerateContentConfig(
        system_instruction=SYSTEM_PROMPT,
        response_mime_type="application/json",
        response_schema=Alert,
        temperature=0.2,
    )
    prompt = f"Write an alert for this vulnerability using only this source material:\n\n{material}"

    for attempt in range(retries):
        try:
            response = client.models.generate_content(model=model, contents=prompt, config=config)
            break
        except errors.APIError as e:
            # 429 = free-tier rate limit; 500/503 = Google overloaded. Wait and retry.
            if e.code in (429, 500, 503) and attempt < retries - 1:
                wait = 30 * (attempt + 1)
                print(f"  Gemini returned {e.code}, waiting {wait}s and retrying...")
                time.sleep(wait)
                continue
            raise

    if isinstance(response.parsed, Alert):
        return response.parsed.model_dump(mode="json")
    return json.loads(response.text)