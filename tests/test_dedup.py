"""Tests for the 3-stage dedup layer."""
import json
import os
import time
import pytest
from unittest.mock import MagicMock, patch

# Ensure worker modules are importable
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'worker'))


class TestStage1Exact:
    def test_compute_alert_hash_deterministic(self):
        from dedup.stage1_exact import compute_alert_hash
        alert = {'rule_name': 'BruteForce', 'source_ip': '10.0.0.99',
                 'hostname': 'WEB-01', 'username': 'admin', 'raw_log': 'test log'}
        h1 = compute_alert_hash(alert)
        h2 = compute_alert_hash(alert)
        assert h1 == h2
        assert len(h1) == 64  # SHA256 hex

    def test_normalize_raw_log_strips_timestamps(self):
        from dedup.stage1_exact import normalize_raw_log
        log1 = "2024-01-15T10:23:01Z Failed password for admin"
        log2 = "2024-01-15T10:24:05Z Failed password for admin"
        assert normalize_raw_log(log1) == normalize_raw_log(log2)

    def test_normalize_raw_log_strips_syslog_timestamps(self):
        from dedup.stage1_exact import normalize_raw_log
        log1 = "Jan 15 10:23:01 sshd: Failed password"
        log2 = "Jan 15 10:24:05 sshd: Failed password"
        assert normalize_raw_log(log1) == normalize_raw_log(log2)

    def test_different_alerts_different_hash(self):
        from dedup.stage1_exact import compute_alert_hash
        alert1 = {'rule_name': 'BruteForce', 'source_ip': '10.0.0.99',
                   'hostname': 'WEB-01', 'username': 'admin', 'raw_log': 'test'}
        alert2 = {'rule_name': 'BruteForce', 'source_ip': '10.0.0.100',
                   'hostname': 'WEB-01', 'username': 'admin', 'raw_log': 'test'}
        assert compute_alert_hash(alert1) != compute_alert_hash(alert2)

    def test_exact_dedup_suppressed(self):
        from dedup.stage1_exact import check_exact_dedup, register_alert
        mock_redis = MagicMock()
        alert = {'rule_name': 'BruteForce', 'source_ip': '10.0.0.99',
                 'hostname': 'WEB-01', 'username': 'admin', 'severity': 'high',
                 'raw_log': 'test'}
        # First call: no existing
        mock_redis.get.return_value = None
        assert check_exact_dedup(alert, mock_redis) is None

        # Register it
        register_alert(alert, 'task-123', mock_redis)
        mock_redis.setex.assert_called_once()
        args = mock_redis.setex.call_args
        assert args[0][1] == 300  # high severity TTL

        # Second call: found
        mock_redis.get.return_value = b'task-123'
        assert check_exact_dedup(alert, mock_redis) == 'task-123'

    def test_critical_severity_short_ttl(self):
        from dedup.stage1_exact import register_alert
        mock_redis = MagicMock()
        alert = {'rule_name': 'APT', 'source_ip': '10.0.0.1', 'severity': 'critical',
                 'raw_log': 'test'}
        register_alert(alert, 'task-456', mock_redis)
        args = mock_redis.setex.call_args
        assert args[0][1] == 60  # critical = 1 min


class TestStage2Correlate:
    def test_first_alert_no_correlation(self):
        from dedup.stage2_correlate import check_correlation
        mock_redis = MagicMock()
        mock_redis.get.return_value = None
        alert = {'rule_name': 'BruteForce', 'source_ip': '10.0.0.99', 'hostname': 'WEB-01'}
        task_id, count = check_correlation(alert, mock_redis)
        assert task_id is None
        assert count == 0

    def test_second_alert_merges(self):
        from dedup.stage2_correlate import check_correlation
        mock_redis = MagicMock()
        record = {'task_id': 'task-111', 'merged_alerts': [{'source_ip': '10.0.0.99'}]}
        mock_redis.get.return_value = json.dumps(record).encode()
        alert = {'rule_name': 'BruteForce', 'source_ip': '10.0.0.99', 'hostname': 'WEB-01'}
        task_id, count = check_correlation(alert, mock_redis)
        assert task_id == 'task-111'
        assert count == 1

    def test_cap_exceeded_spawns_new(self):
        from dedup.stage2_correlate import check_correlation, MAX_MERGED_ALERTS
        mock_redis = MagicMock()
        record = {'task_id': 'task-111', 'merged_alerts': [{}] * MAX_MERGED_ALERTS}
        mock_redis.get.return_value = json.dumps(record).encode()
        alert = {'rule_name': 'BruteForce', 'source_ip': '10.0.0.99', 'hostname': 'WEB-01'}
        task_id, count = check_correlation(alert, mock_redis)
        assert task_id is None  # Cap exceeded, spawn new


class TestStage3Semantic:
    def test_extract_fingerprint(self):
        from dedup.stage3_semantic import extract_behavioral_fingerprint
        alert = {'rule_name': 'BruteForce', 'task_type': 'brute_force',
                 'raw_log': 'Failed password for admin from 10.0.0.99'}
        fp = extract_behavioral_fingerprint(alert)
        assert 'BruteForce' in fp
        assert 'Failed password' in fp

    def test_semantic_dedup_no_model_returns_none(self):
        from dedup.stage3_semantic import check_semantic_dedup
        with patch.dict(os.environ, {'EMBEDDING_MODEL_PATH': '/nonexistent/path'}):
            result = check_semantic_dedup({'rule_name': 'test', 'raw_log': 'test'}, MagicMock())
            assert result is None


class TestOrchestrator:
    def test_dedup_disabled_bypasses_all(self):
        from dedup.orchestrator import DedupOrchestrator
        with patch.dict(os.environ, {'DEDUP_ENABLED': 'false'}):
            orch = DedupOrchestrator(redis_client=MagicMock())
            action, reason, task_id = orch.process({'rule_name': 'test'})
            assert action == 'new'
            assert reason == 'dedup_disabled'

    def test_exact_match_returns_duplicate(self):
        from dedup.orchestrator import DedupOrchestrator
        mock_redis = MagicMock()
        mock_redis.get.return_value = b'task-existing'
        with patch.dict(os.environ, {'DEDUP_ENABLED': 'true'}):
            orch = DedupOrchestrator(redis_client=mock_redis)
            action, reason, task_id = orch.process(
                {'rule_name': 'BF', 'source_ip': '1.2.3.4', 'severity': 'high', 'raw_log': 'x'})
            assert action == 'duplicate'
            assert task_id == 'task-existing'

    def test_no_match_returns_new(self):
        from dedup.orchestrator import DedupOrchestrator
        mock_redis = MagicMock()
        mock_redis.get.return_value = None
        with patch.dict(os.environ, {'DEDUP_ENABLED': 'true'}):
            orch = DedupOrchestrator(redis_client=mock_redis, db_conn=None)
            action, reason, task_id = orch.process(
                {'rule_name': 'BF', 'source_ip': '1.2.3.4', 'raw_log': 'x'})
            assert action == 'new'
            assert reason == 'no_match'
