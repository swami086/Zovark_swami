"""
Sprint 5 integration tests.
Run inside worker container:
  docker compose exec -T worker python -m pytest tests/integration/test_sprint5.py -v
"""
import pytest
import asyncio


class TestDryRunGate:
    """Test 2-3: Dry-run validation catches bad code."""

    @pytest.mark.asyncio
    async def test_missing_keys_rejected(self):
        """Code that returns wrong keys should fail validation."""
        from validation.dry_run import DryRunValidator
        validator = DryRunValidator(timeout=5)
        bad_code = 'result = {"wrong_key": "bad"}'
        result = await validator.validate(bad_code)
        assert not result['passed']
        assert 'Missing required keys' in result['reason']

    @pytest.mark.asyncio
    async def test_valid_code_passes(self):
        """Code with correct keys should pass."""
        from validation.dry_run import DryRunValidator
        validator = DryRunValidator(timeout=5)
        good_code = '''result = {
    "findings": ["Test finding"],
    "confidence": 0.95,
    "entities": [{"type": "ip", "value": "1.2.3.4", "context": "test"}],
    "verdict": "benign"
}'''
        result = await validator.validate(good_code)
        assert result['passed']

    @pytest.mark.asyncio
    async def test_infinite_loop_rejected(self):
        """Code with infinite loop should fail static check."""
        from validation.dry_run import DryRunValidator
        validator = DryRunValidator(timeout=5)
        bad_code = 'while True:\n    pass'
        result = await validator.validate(bad_code)
        assert not result['passed']

    @pytest.mark.asyncio
    async def test_syntax_error_rejected(self):
        """Code with syntax errors should fail static check."""
        from validation.dry_run import DryRunValidator
        validator = DryRunValidator(timeout=5)
        bad_code = 'def foo(\n  incomplete'
        result = await validator.validate(bad_code)
        assert not result['passed']
        assert 'Syntax error' in result['reason']

    @pytest.mark.asyncio
    async def test_network_call_rejected(self):
        """Code with network calls should fail static check."""
        from validation.dry_run import DryRunValidator
        validator = DryRunValidator(timeout=5)
        bad_code = 'import requests\nresult = requests.get("http://evil.com")'
        result = await validator.validate(bad_code)
        assert not result['passed']
        assert 'Network call' in result['reason']

    @pytest.mark.asyncio
    async def test_invalid_verdict_rejected(self):
        """Code with invalid verdict should fail validation."""
        from validation.dry_run import DryRunValidator
        validator = DryRunValidator(timeout=5)
        bad_code = '''result = {
    "findings": ["test"],
    "confidence": 0.5,
    "entities": [],
    "verdict": "maybe_bad"
}'''
        result = await validator.validate(bad_code)
        assert not result['passed']
        assert 'Invalid verdict' in result['reason']


class TestInvestigationMemory:
    """Test 4-5: Memory exact match and semantic search."""

    def test_memory_module_imports(self):
        """Verify InvestigationMemory can be imported."""
        from investigation_memory import InvestigationMemory
        assert InvestigationMemory is not None

    def test_memory_thresholds_exist(self):
        """Verify per-entity-type thresholds are defined."""
        from investigation_memory import SIMILARITY_THRESHOLDS
        assert 'ip' in SIMILARITY_THRESHOLDS
        assert 'domain' in SIMILARITY_THRESHOLDS
        assert 'file_hash' in SIMILARITY_THRESHOLDS
        assert SIMILARITY_THRESHOLDS['file_hash'] < SIMILARITY_THRESHOLDS['domain']


class TestInvestigationPrompt:
    """Test prompt building with memory."""

    def test_prompt_without_memory(self):
        """Prompt builds correctly with no memory."""
        from prompts.investigation_prompt import build_investigation_prompt
        alert = {'task_type': 'brute_force', 'source': 'SIEM', 'input': {'prompt': 'test'}}
        prompt = build_investigation_prompt(alert)
        assert 'brute_force' in prompt
        assert 'No prior investigations' in prompt

    def test_prompt_with_exact_matches(self):
        """Prompt includes exact match context."""
        from prompts.investigation_prompt import build_investigation_prompt
        alert = {'task_type': 'brute_force', 'source': 'SIEM', 'input': {'prompt': 'test'}}
        memory = {
            'exact_matches': [{
                'entity': '10.0.0.1',
                'type': 'ip',
                'conclusion': 'malicious',
                'confidence': 0.95,
                'investigation_id': 'abc-123',
                'seen_at': '2026-01-01',
            }],
            'similar_entities': []
        }
        prompt = build_investigation_prompt(alert, memory)
        assert 'EXACT MATCHES' in prompt
        assert '10.0.0.1' in prompt
        assert 'malicious' in prompt


class TestModelConfig:
    """Test model tier configuration."""

    def test_tiers_use_hydra_prefix(self):
        """Model names should use hydra-* prefix."""
        from model_config import MODEL_TIERS
        assert MODEL_TIERS['fast']['model'] == 'hydra-fast'
        assert MODEL_TIERS['standard']['model'] == 'hydra-standard'
        assert MODEL_TIERS['reasoning']['model'] == 'hydra-reasoning'

    def test_tier_config_returns_correct_model(self):
        """get_tier_config returns hydra-* model names (when no env override)."""
        import os
        old_val = os.environ.get('HYDRA_LLM_MODEL')
        os.environ['HYDRA_LLM_MODEL'] = ''
        try:
            from model_config import get_tier_config
            config = get_tier_config('generate_code')
            assert config['model'] == 'hydra-standard'
            assert config['tier'] == 'standard'
        finally:
            if old_val is not None:
                os.environ['HYDRA_LLM_MODEL'] = old_val
            elif 'HYDRA_LLM_MODEL' in os.environ:
                del os.environ['HYDRA_LLM_MODEL']


class TestSkillRouting:
    """Test skill selection."""

    def test_skills_exist_in_db(self):
        """Verify agent_skills table has data."""
        import psycopg2
        import os
        db_url = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
        conn = psycopg2.connect(db_url)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM agent_skills WHERE is_active = true")
                count = cur.fetchone()[0]
                assert count >= 5, f"Expected at least 5 active skills, got {count}"
        finally:
            conn.close()
