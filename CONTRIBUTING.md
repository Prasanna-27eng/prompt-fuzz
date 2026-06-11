# Contributing to prompt-fuzz

Contributions are welcome — especially new payloads and detectors.

## Adding a payload

Edit `src/promptfuzz/data/payloads.json` (or create a custom file with the
same schema and pass `--payloads`). Each entry:

```json
{
  "id": "unique_snake_case_id",
  "name": "Human-readable name",
  "category": "jailbreak | system_override | role_hijack | instruction_inject | delimiter_inject | role_delimiter | exfiltration | xml_inject | template_inject | encoding_bypass",
  "severity": "low | medium | high | critical",
  "prompt": "The actual payload text sent as the user message.",
  "success_markers": ["Optional list of phrases that indicate compliance, e.g. 'DAN Mode enabled'"],
  "references": ["Optional CWE / MITRE ATLAS IDs"]
}
```

- `id` must be unique across the library (`tests/test_payloads.py` enforces this).
- `success_markers` should match a literal phrase the payload *asks* the
  model to say if it complies — not a guess at arbitrary output.
- If your payload targets a new attack class, add a small "weak guardrail"
  trigger to `mock_target/app.py` so `prompt-fuzz`'s own test suite can
  exercise both the BLOCKED and BYPASSED paths deterministically.

## Adding a detector

`src/promptfuzz/detectors.py` combines independent signals into a
`Verdict`. New detectors should:
- Be a pure function over `(response_text, payload, canary)`.
- Never make network calls.
- Be wired into `evaluate()` and covered by `tests/test_detectors.py`.

## Running tests

```bash
pip install -e ".[dev]"
pytest
```

## Reporting a vulnerability in prompt-fuzz itself

prompt-fuzz is offensive tooling intended for use against your own LLM
deployments or systems you have explicit permission to test. If you find a
bug that could cause prompt-fuzz itself to be misused beyond its documented
scope, please open an issue describing the problem.
