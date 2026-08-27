"""Cross-language RFC 8785 JSON Canonicalization Scheme vectors."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from hlinor_registry import canonical_json_bytes

VECTOR_PATH = Path(__file__).parent / "fixtures" / "jcs-golden-vectors.json"


def _vectors() -> list[dict[str, Any]]:
    document = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    assert document["format"] == "hlinor-jcs-golden-vectors/1"
    assert document["encoding"] == "UTF-8"
    return document["vectors"]


def test_rfc8785_vectors_match_canonical_utf8_and_sha256() -> None:
    for vector in _vectors():
        canonical = canonical_json_bytes(vector["value"])
        assert canonical.decode("utf-8") == vector["canonical_json"], vector["id"]
        assert hashlib.sha256(canonical).hexdigest() == vector["sha256"], vector["id"]


def test_rfc8785_vectors_have_unique_ids_and_non_empty_payloads() -> None:
    vectors = _vectors()
    ids = [vector["id"] for vector in vectors]
    assert len(ids) == len(set(ids))
    assert all(vector["canonical_json"] for vector in vectors)
    assert all(len(vector["sha256"]) == 64 for vector in vectors)
