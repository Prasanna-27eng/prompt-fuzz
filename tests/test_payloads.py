from promptfuzz import payloads as payload_lib


def test_builtin_payloads_load():
    payloads = payload_lib.load_builtin_payloads()
    assert len(payloads) >= 40

    required_keys = {"id", "name", "category", "severity", "prompt"}
    ids = set()
    for p in payloads:
        assert required_keys.issubset(p.keys())
        assert p["id"] not in ids, f"duplicate payload id: {p['id']}"
        ids.add(p["id"])


def test_filter_by_category():
    payloads = payload_lib.load_builtin_payloads()
    jailbreaks = payload_lib.filter_by_category(payloads, ["jailbreak"])
    assert jailbreaks
    assert all(p["category"] == "jailbreak" for p in jailbreaks)


def test_list_categories():
    payloads = payload_lib.load_builtin_payloads()
    cats = payload_lib.list_categories(payloads)
    assert "jailbreak" in cats
    assert "system_override" in cats
    assert "encoding_bypass" in cats


def test_canary_and_system_prompt():
    canary = payload_lib.make_canary()
    assert canary.startswith(payload_lib.CANARY_PREFIX)

    prompt = payload_lib.make_system_prompt(canary)
    assert canary in prompt
