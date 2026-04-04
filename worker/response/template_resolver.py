"""Playbook template variable resolution.

Resolves {{variable}} placeholders in playbook action contexts
using investigation data and extracted entities.

Usage:
    resolver = PlaybookTemplateResolver()
    resolved = resolver.resolve("Block {{attacker_ip}}", investigation_data)
"""
import re
import os

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    from database.pool_manager import pooled_connection
except ImportError:
    psycopg2 = None
    RealDictCursor = None
    pooled_connection = None


class PlaybookTemplateResolver:
    """Resolves template variables in playbook action contexts."""

    VARIABLE_MAP = {
        'attacker_ip': 'entities[type=ip_address,role=attacker].value',
        'victim_ip': 'entities[type=ip_address,role=victim].value',
        'source_host': 'entities[type=hostname,role=source].value',
        'dest_host': 'entities[type=hostname,role=destination].value',
        'alert_id': 'investigation.alert_id',
        'investigation_id': 'investigation.id',
        'risk_score': 'investigation.risk_score',
        'mitre_technique': 'investigation.mitre_techniques[0]',
        'timestamp': 'investigation.created_at',
        'tenant_id': 'investigation.tenant_id',
        'severity': 'investigation.severity',
        'finding_summary': 'investigation.findings_summary',
        'ioc_list': 'entities[type in (ip_address,domain,hash)].values_csv',
        'affected_users': 'entities[type=user].values_csv',
    }

    # Regex: matches {{variable_name}} but NOT nested resolution
    _TEMPLATE_RE = re.compile(r'\{\{(\w+)\}\}')

    def resolve(self, template_str: str, investigation_data: dict) -> str:
        """Resolve all {{variable}} placeholders in a template string.

        Unresolved variables become [UNKNOWN:variable_name].
        Values are string-escaped to prevent re-resolution (no nested templates).
        """
        if not template_str or '{{' not in template_str:
            return template_str

        def _replacer(match):
            var_name = match.group(1)
            value = self._lookup(var_name, investigation_data)
            if value is None:
                return f'[UNKNOWN:{var_name}]'
            # Sanitize: strip any {{ }} from resolved values to prevent re-resolution
            safe_value = str(value).replace('{{', '').replace('}}', '')
            return safe_value

        # Single pass — no re-resolution
        return self._TEMPLATE_RE.sub(_replacer, template_str)

    def resolve_action_context(self, action: dict, investigation_data: dict) -> dict:
        """Resolve template variables in all string values of an action context dict."""
        resolved = {}
        for key, value in action.items():
            if isinstance(value, str):
                resolved[key] = self.resolve(value, investigation_data)
            elif isinstance(value, dict):
                resolved[key] = self.resolve_action_context(value, investigation_data)
            elif isinstance(value, list):
                resolved[key] = [
                    self.resolve(item, investigation_data) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                resolved[key] = value
        return resolved

    def _lookup(self, var_name: str, data: dict):
        """Look up a variable value from investigation data."""
        inv = data.get('investigation', {})
        entities = data.get('entities', [])

        if var_name == 'attacker_ip':
            return self._find_entity(entities, 'ip_address', role='attacker')
        elif var_name == 'victim_ip':
            return self._find_entity(entities, 'ip_address', role='victim')
        elif var_name == 'source_host':
            return self._find_entity(entities, 'hostname', role='source')
        elif var_name == 'dest_host':
            return self._find_entity(entities, 'hostname', role='destination')
        elif var_name == 'alert_id':
            return inv.get('alert_id') or inv.get('source_alert_id')
        elif var_name == 'investigation_id':
            return inv.get('id')
        elif var_name == 'risk_score':
            return inv.get('risk_score')
        elif var_name == 'mitre_technique':
            techniques = inv.get('mitre_techniques', [])
            return techniques[0] if techniques else None
        elif var_name == 'timestamp':
            return inv.get('created_at')
        elif var_name == 'tenant_id':
            return inv.get('tenant_id')
        elif var_name == 'severity':
            return inv.get('severity')
        elif var_name == 'finding_summary':
            return inv.get('findings_summary') or inv.get('summary')
        elif var_name == 'ioc_list':
            return self._collect_entities_csv(entities, ('ip_address', 'domain', 'hash'))
        elif var_name == 'affected_users':
            return self._collect_entities_csv(entities, ('user',))
        return None

    def _find_entity(self, entities: list, entity_type: str, role: str = None) -> str:
        """Find first entity matching type and optional role."""
        for e in entities:
            if e.get('entity_type') == entity_type or e.get('type') == entity_type:
                if role is None or e.get('role') == role:
                    return e.get('value') or e.get('entity_value')
        # Fallback: return any entity of matching type (ignore role)
        if role:
            for e in entities:
                if e.get('entity_type') == entity_type or e.get('type') == entity_type:
                    return e.get('value') or e.get('entity_value')
        return None

    def _collect_entities_csv(self, entities: list, types: tuple) -> str:
        """Collect all entity values matching any of the given types as CSV."""
        values = []
        for e in entities:
            etype = e.get('entity_type') or e.get('type')
            if etype in types:
                val = e.get('value') or e.get('entity_value')
                if val and val not in values:
                    values.append(val)
        return ', '.join(values) if values else None


def fetch_investigation_data(investigation_id: str, tenant_id: str) -> dict:
    """Fetch investigation + entities from DB for template resolution."""
    with pooled_connection("normal") as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Fetch investigation
            cur.execute(
                "SELECT id, tenant_id, alert_id, risk_score, severity, "
                "mitre_techniques, created_at, summary, findings_summary "
                "FROM investigations WHERE id = %s AND tenant_id = %s",
                (investigation_id, tenant_id)
            )
            inv_row = cur.fetchone()

            # Fetch entities
            cur.execute(
                "SELECT entity_type, entity_value AS value, role "
                "FROM entity_observations WHERE investigation_id = %s",
                (investigation_id,)
            )
            entity_rows = cur.fetchall()

    investigation = dict(inv_row) if inv_row else {}
    if investigation.get('id'):
        investigation['id'] = str(investigation['id'])

    entities = [dict(e) for e in entity_rows] if entity_rows else []

    return {
        'investigation': investigation,
        'entities': entities,
    }
