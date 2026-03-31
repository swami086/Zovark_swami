"""Tests for scoring tools."""
import pytest
from tools.scoring import (
    score_brute_force, score_phishing, score_lateral_movement,
    score_exfiltration, score_c2_beacon, score_generic,
)


class TestScoreBruteForce:
    def test_high_volume(self):
        score = score_brute_force(500, 1, 5)
        assert 90 <= score <= 100

    def test_low_volume(self):
        score = score_brute_force(3, 1, 60)
        assert 0 <= score <= 30

    def test_zero(self):
        score = score_brute_force(0, 0, 0)
        assert 0 <= score <= 15


class TestScorePhishing:
    def test_all_indicators(self):
        score = score_phishing(3, 2, True, True)
        assert 80 <= score <= 100

    def test_no_indicators(self):
        score = score_phishing(0, 0, False, False)
        assert 0 <= score <= 15


class TestScoreLateralMovement:
    def test_high_risk(self):
        score = score_lateral_movement("psexec", True, True, True)
        assert 90 <= score <= 100

    def test_low_risk(self):
        score = score_lateral_movement("ssh", False, False, False)
        assert 10 <= score <= 40


class TestScoreExfiltration:
    def test_large_external(self):
        score = score_exfiltration(1073741824, True, True, True)
        assert 85 <= score <= 100

    def test_small_internal(self):
        score = score_exfiltration(1024, False, False, False)
        assert 0 <= score <= 20


class TestScoreC2Beacon:
    def test_regular_beacon(self):
        score = score_c2_beacon(0.5, 30.0, 500, 4.5)
        assert 80 <= score <= 100

    def test_irregular(self):
        score = score_c2_beacon(120.0, 300.0, 5, 2.0)
        assert 0 <= score <= 30


class TestScoreGeneric:
    def test_high_severity(self):
        score = score_generic(5, 3, 2)
        assert 70 <= score <= 100

    def test_no_indicators(self):
        score = score_generic(0, 0, 0)
        assert 0 <= score <= 15
