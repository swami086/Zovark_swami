import os
from typing import Tuple, Optional


class DedupOrchestrator:
    def __init__(self, redis_client, db_conn=None):
        self.redis = redis_client
        self.db_conn = db_conn

    def process(self, alert: dict) -> Tuple[str, str, Optional[str]]:
        if os.environ.get('DEDUP_ENABLED', 'true').lower() != 'true':
            return ('new', 'dedup_disabled', None)

        # Stage 1: Exact dedup
        from dedup.stage1_exact import check_exact_dedup
        existing = check_exact_dedup(alert, self.redis)
        if existing:
            return ('duplicate', 'exact_match', existing)

        # Stage 2: Correlation window
        from dedup.stage2_correlate import check_correlation, merge_alert
        corr_task, count = check_correlation(alert, self.redis)
        if corr_task:
            merge_alert(alert, corr_task, self.redis)
            return ('merged', f'correlated_count_{count + 1}', corr_task)

        # Stage 3: Semantic (only if DB available)
        if self.db_conn:
            try:
                from dedup.stage3_semantic import check_semantic_dedup
                semantic_match = check_semantic_dedup(alert, self.db_conn)
                if semantic_match:
                    return ('similar', 'semantic_match', semantic_match)
            except Exception as e:
                print(f"Semantic dedup failed non-fatally: {e}")

        return ('new', 'no_match', None)
