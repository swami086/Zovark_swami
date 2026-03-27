"""SRE Monitor — scans Temporal + DB for workflow/activity failures."""

import os
from datetime import datetime, timedelta, timezone
from temporalio import activity

import psycopg2
from psycopg2.extras import RealDictCursor
from temporalio.client import Client


def get_db_connection():
    db_url = os.environ.get("DATABASE_URL", "postgresql://zovarc:zovarc_dev_2026@postgres:5432/zovarc")
    return psycopg2.connect(db_url)


def _extract_failure_info(workflow_info, events):
    """Extract failure details from workflow history events."""
    failures = []
    workflow_id = workflow_info.id if hasattr(workflow_info, 'id') else str(workflow_info)

    for event in events:
        event_type = str(event.event_type)

        # Activity task failed
        if 'ACTIVITY_TASK_FAILED' in event_type:
            attrs = getattr(event, 'activity_task_failed_event_attributes', None)
            if attrs:
                failure = attrs.failure if hasattr(attrs, 'failure') else None
                error_message = str(failure.message) if failure and hasattr(failure, 'message') else 'Unknown error'
                stack_trace = str(failure.stack_trace) if failure and hasattr(failure, 'stack_trace') else ''
                activity_name = ''
                scheduled_id = getattr(attrs, 'scheduled_event_id', None)
                if scheduled_id:
                    for e2 in events:
                        if e2.event_id == scheduled_id:
                            sched_attrs = getattr(e2, 'activity_task_scheduled_event_attributes', None)
                            if sched_attrs and hasattr(sched_attrs, 'activity_type'):
                                activity_name = sched_attrs.activity_type.name
                            break

                failures.append({
                    'workflow_id': workflow_id,
                    'activity_name': activity_name,
                    'error_message': error_message,
                    'stack_trace': stack_trace[:2000],
                    'timestamp': event.event_time.isoformat() if hasattr(event, 'event_time') else datetime.now(timezone.utc).isoformat(),
                    'source': 'temporal',
                })

        # Workflow execution failed
        elif 'WORKFLOW_EXECUTION_FAILED' in event_type:
            attrs = getattr(event, 'workflow_execution_failed_event_attributes', None)
            if attrs:
                failure = attrs.failure if hasattr(attrs, 'failure') else None
                error_message = str(failure.message) if failure and hasattr(failure, 'message') else 'Workflow failed'
                stack_trace = str(failure.stack_trace) if failure and hasattr(failure, 'stack_trace') else ''

                failures.append({
                    'workflow_id': workflow_id,
                    'activity_name': '',
                    'error_message': error_message,
                    'stack_trace': stack_trace[:2000],
                    'timestamp': event.event_time.isoformat() if hasattr(event, 'event_time') else datetime.now(timezone.utc).isoformat(),
                    'source': 'temporal',
                })

    return failures


@activity.defn
async def scan_for_failures(data: dict) -> dict:
    """Scan Temporal and agent_tasks DB for recent failures."""
    lookback_minutes = data.get("lookback_minutes", 30)
    lookback_iso = (datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)).isoformat()

    all_failures = []

    # 1. Scan Temporal for failed workflows
    try:
        temporal_addr = os.environ.get("TEMPORAL_ADDRESS", "temporal:7233")
        client = await Client.connect(temporal_addr)

        query = f"ExecutionStatus='Failed' AND CloseTime > '{lookback_iso}'"
        async for workflow_info in client.list_workflows(query=query):
            try:
                handle = client.get_workflow_handle(workflow_info.id, run_id=workflow_info.run_id)
                history = await handle.fetch_history()
                failures = _extract_failure_info(workflow_info, history.events)
                all_failures.extend(failures)
            except Exception as e:
                print(f"scan_for_failures: error fetching history for {workflow_info.id}: {e}")
    except Exception as e:
        print(f"scan_for_failures: Temporal scan error: {e}")

    # 2. Scan agent_tasks DB for failed tasks
    try:
        conn = get_db_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT id::text, workflow_id, task_type, error_message, created_at
                    FROM agent_tasks
                    WHERE status = 'failed'
                    AND created_at > NOW() - INTERVAL '%s minutes'
                    ORDER BY created_at DESC
                    LIMIT 50
                """, (lookback_minutes,))
                rows = cur.fetchall()
                for row in rows:
                    if row.get('error_message'):
                        all_failures.append({
                            'workflow_id': row.get('workflow_id', ''),
                            'activity_name': row.get('task_type', ''),
                            'error_message': row['error_message'],
                            'stack_trace': '',
                            'timestamp': row['created_at'].isoformat() if row.get('created_at') else '',
                            'source': 'database',
                        })
        finally:
            conn.close()
    except Exception as e:
        print(f"scan_for_failures: DB scan error: {e}")

    # Deduplicate by error_message
    seen = set()
    unique_failures = []
    for f in all_failures:
        key = f['error_message'][:200]
        if key not in seen:
            seen.add(key)
            unique_failures.append(f)

    return {
        'failures': unique_failures,
        'count': len(unique_failures),
        'lookback_minutes': lookback_minutes,
    }
