"""Registration helper for V2 pipeline stages."""


def get_v2_activities():
    """Return all V2 stage activities for Temporal worker registration."""
    from .ingest import ingest_alert
    from .analyze import analyze_alert
    from .execute import execute_investigation
    from .assess import assess_results
    from .store import store_investigation
    return [ingest_alert, analyze_alert, execute_investigation,
            assess_results, store_investigation]


def get_v2_workflows():
    """Return all V2 workflows for Temporal worker registration."""
    from .investigation_workflow import InvestigationWorkflowV2
    return [InvestigationWorkflowV2]
