# Re-export all activity functions from the renamed legacy module.
from _legacy_activities import (  # noqa: F401
    fetch_task, generate_code, validate_code, execute_code,
    update_task_status, log_audit, log_audit_event, record_usage,
    save_investigation_step, check_followup_needed, generate_followup_code,
    check_requires_approval, create_approval_request, update_approval_request,
    retrieve_skill, write_investigation_memory, fill_skill_parameters,
    render_skill_template, check_rate_limit_activity, decrement_active_activity,
    heartbeat_lease_activity, validate_generated_code, enrich_alert_with_memory,
    get_db_connection,
)
