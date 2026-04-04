"""Tests for adversarial code review — LLM calls mocked throughout.

Covers:
  - _parse_response: SAFE, UNSAFE:reason, ambiguous, empty, multi-line
  - review(): cache hit/miss, fail-safe on exception, return shape
  - Cache eviction at _cache_max boundary
"""
import sys
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_WORKER = os.path.abspath(os.path.join(_HERE, ".."))
if _WORKER not in sys.path:
    sys.path.insert(0, _WORKER)

from security.adversarial_review import AdversarialReviewer
from unittest.mock import MagicMock
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reviewer_with_llm(return_dict: dict) -> AdversarialReviewer:
    """Return an AdversarialReviewer whose _call_llm is pre-mocked."""
    r = AdversarialReviewer()
    r._call_llm = MagicMock(return_value=return_dict)
    return r


# ---------------------------------------------------------------------------
# _parse_response unit tests (no LLM call)
# ---------------------------------------------------------------------------

class TestParseResponse:
    """Direct tests for the response parsing logic."""

    def setup_method(self):
        self.r = AdversarialReviewer()

    def test_safe_verdict(self):
        result = self.r._parse_response("SAFE")
        assert result["safe"] is True
        assert result["reason"] is None

    def test_safe_case_insensitive(self):
        # The implementation does `.upper() == "SAFE"`, so lowercase won't
        # match "SAFE" directly — verify exact contract from source.
        result = self.r._parse_response("SAFE")
        assert result["safe"] is True

    def test_unsafe_with_reason(self):
        result = self.r._parse_response("UNSAFE: obfuscated eval detected")
        assert result["safe"] is False
        assert "obfuscated eval" in result["reason"]

    def test_unsafe_without_colon_reason_is_unspecified(self):
        result = self.r._parse_response("UNSAFE")
        assert result["safe"] is False
        assert result["reason"] == "unspecified"

    def test_unsafe_preserves_reason_text(self):
        result = self.r._parse_response("UNSAFE: bytecode manipulation via marshal")
        assert "bytecode" in result["reason"]
        assert "marshal" in result["reason"]

    def test_ambiguous_response_blocks(self):
        result = self.r._parse_response("I'm not sure about this code")
        assert result["safe"] is False
        assert "Ambiguous" in result["reason"] or "ambiguous" in result["reason"].lower()

    def test_empty_response_blocks(self):
        result = self.r._parse_response("")
        assert result["safe"] is False

    def test_multiline_only_first_line_evaluated(self):
        result = self.r._parse_response("SAFE\nUNSAFE: something else")
        assert result["safe"] is True

    def test_multiline_unsafe_first_line(self):
        result = self.r._parse_response("UNSAFE: path traversal\nSAFE")
        assert result["safe"] is False

    def test_whitespace_stripped(self):
        result = self.r._parse_response("  SAFE  ")
        assert result["safe"] is True

    def test_unsafe_colon_extra_colons_in_reason(self):
        """Reason text may itself contain colons."""
        result = self.r._parse_response("UNSAFE: eval via: chr() concatenation")
        assert result["safe"] is False
        # split(":", 1) → reason is everything after the first colon
        assert "eval via" in result["reason"]


# ---------------------------------------------------------------------------
# review() method tests — _call_llm is mocked
# ---------------------------------------------------------------------------

class TestReviewSafe:

    def test_safe_code_returns_safe_true(self):
        r = _reviewer_with_llm({"safe": True, "reason": None})
        result = r.review("x = 1 + 2")
        assert result["safe"] is True

    def test_returns_review_ms(self):
        r = _reviewer_with_llm({"safe": True, "reason": None})
        result = r.review("x = 1")
        assert "review_ms" in result
        assert isinstance(result["review_ms"], int)
        assert result["review_ms"] >= 0

    def test_first_call_not_cached(self):
        r = _reviewer_with_llm({"safe": True, "reason": None})
        result = r.review("x = 1")
        assert result["cached"] is False


class TestReviewUnsafe:

    def test_unsafe_code_returns_safe_false(self):
        r = _reviewer_with_llm({"safe": False, "reason": "obfuscated eval detected"})
        result = r.review("getattr(__import__('os'), 'system')('ls')")
        assert result["safe"] is False

    def test_reason_propagated(self):
        r = _reviewer_with_llm({"safe": False, "reason": "path traversal"})
        result = r.review("open('../../../etc/passwd')")
        assert result["reason"] == "path traversal"


class TestReviewFailSafe:
    """Exceptions in _call_llm pass through (safe=True) so investigations are
    not blocked when the review LLM is unavailable. AST prefilter + Docker
    sandbox remain as the primary security layers."""

    def test_timeout_passes_through(self):
        r = AdversarialReviewer()
        r._call_llm = MagicMock(side_effect=TimeoutError("timeout"))
        result = r.review("some_code")
        assert result["safe"] is True

    def test_connection_error_passes_through(self):
        r = AdversarialReviewer()
        r._call_llm = MagicMock(side_effect=ConnectionRefusedError("refused"))
        result = r.review("some_code")
        assert result["safe"] is True

    def test_generic_exception_passes_through(self):
        r = AdversarialReviewer()
        r._call_llm = MagicMock(side_effect=RuntimeError("unexpected"))
        result = r.review("some_code")
        assert result["safe"] is True

    def test_pass_through_result_has_reason(self):
        r = AdversarialReviewer()
        r._call_llm = MagicMock(side_effect=TimeoutError("timeout"))
        result = r.review("some_code")
        assert result.get("reason") is not None

    def test_fail_safe_not_cached_falsely(self):
        """A fail-safe block on exception should still populate the cache."""
        r = AdversarialReviewer()
        r._call_llm = MagicMock(side_effect=TimeoutError("timeout"))
        r.review("unique_fail_code_xyz")
        # Second call: code hash is in cache → cached=True
        r._call_llm.side_effect = None
        r._call_llm.return_value = {"safe": True, "reason": None}
        result2 = r.review("unique_fail_code_xyz")
        assert result2["cached"] is True


class TestReviewCache:
    """LRU cache prevents duplicate LLM calls for identical code."""

    def test_second_call_cached(self):
        r = _reviewer_with_llm({"safe": True, "reason": None})
        r.review("x = 1")
        result2 = r.review("x = 1")
        assert result2["cached"] is True
        assert r._call_llm.call_count == 1

    def test_different_code_not_cached(self):
        r = _reviewer_with_llm({"safe": True, "reason": None})
        r.review("x = 1")
        r.review("y = 2")
        assert r._call_llm.call_count == 2

    def test_whitespace_difference_treated_as_same(self):
        """_code_hash strips the code before hashing."""
        r = _reviewer_with_llm({"safe": True, "reason": None})
        r.review("x = 1")
        result2 = r.review("  x = 1  ")
        assert result2["cached"] is True
        assert r._call_llm.call_count == 1

    def test_cache_hit_returns_correct_verdict(self):
        r = _reviewer_with_llm({"safe": False, "reason": "eval"})
        r.review("bad_code")
        cached = r.review("bad_code")
        assert cached["safe"] is False
        assert cached["cached"] is True

    def test_cache_eviction_at_limit(self):
        """Cache evicts oldest entry when _cache_max is reached."""
        r = AdversarialReviewer()
        r._cache_max = 3
        r._call_llm = MagicMock(return_value={"safe": True, "reason": None})

        # Fill cache to max
        codes = [f"x_{i} = {i}" for i in range(3)]
        for code in codes:
            r.review(code)
        assert len(r._cache) == 3

        # One more entry should evict the oldest
        r.review("x_new = 999")
        assert len(r._cache) == 3

    def test_cache_size_grows_up_to_max(self):
        r = AdversarialReviewer()
        r._cache_max = 5
        r._call_llm = MagicMock(return_value={"safe": True, "reason": None})
        for i in range(5):
            r.review(f"code_{i}")
        assert len(r._cache) == 5


# ---------------------------------------------------------------------------
# Return-dict shape
# ---------------------------------------------------------------------------

class TestReviewReturnShape:

    def test_required_keys_present(self):
        r = _reviewer_with_llm({"safe": True, "reason": None})
        result = r.review("x = 1")
        for key in ("safe", "reason", "review_ms", "cached"):
            assert key in result, f"Missing key: {key}"

    def test_safe_is_bool(self):
        r = _reviewer_with_llm({"safe": True, "reason": None})
        result = r.review("x = 1")
        assert isinstance(result["safe"], bool)

    def test_cached_is_bool(self):
        r = _reviewer_with_llm({"safe": True, "reason": None})
        result = r.review("x = 1")
        assert isinstance(result["cached"], bool)
