# Zovark 48-Hour Proof of Value

## Day 1 Morning: Deploy (30 minutes)

1. Run `bash scripts/pov/deploy.sh` on your server
2. Open http://localhost:3000, log in with `pov-admin` / `PoV-2026-Zovark!`
3. Verify all services healthy in Grafana (http://localhost:3001)

## Day 1 Afternoon: Historical Analysis (3 hours)

1. Export 100 recent alerts from your SIEM (CSV or JSON)
2. Import:
   ```bash
   python scripts/pov/import_alerts.py \
     --format splunk --file alerts.csv \
     --tenant-id <your-tenant-id>
   ```
3. Watch investigations complete in the dashboard
4. Review: entity extraction, risk scores, findings

### Supported SIEM Formats

| Format | Flag | File Type |
|--------|------|-----------|
| Splunk | `--format splunk` | CSV export |
| Microsoft Sentinel | `--format sentinel` | JSON incidents |
| QRadar | `--format qradar` | XML offenses |
| Generic | `--format generic` | JSON array |

## Day 2 Morning: Live Parallel (4 hours)

1. Configure SIEM webhook to forward alerts to Zovark:
   ```
   POST http://zovark-server:8090/api/v1/webhooks/<source_id>/alert
   ```
2. Run Zovark in parallel with your analysts
3. Compare: which alerts did Zovark flag that analysts missed?

## Day 2 Afternoon: Results (2 hours)

1. Generate report:
   ```bash
   python scripts/pov/generate_report.py \
     --tenant-id <your-tenant-id> \
     --output report.html
   ```
2. Review side-by-side comparison
3. Calculate ROI: analyst hours saved x $75/hr x 250 days

## Success Criteria

- [ ] >80% accuracy on historical alerts
- [ ] >10x faster than manual investigation
- [ ] >90% analyst satisfaction (useful findings)
- [ ] Zero false negatives on critical alerts

## Troubleshooting

| Issue | Fix |
|-------|-----|
| API not responding | `docker compose logs api` |
| Worker not processing | `docker compose logs worker` |
| DB connection error | `docker compose logs postgres` |
| Out of memory | Increase Docker memory limit to 8GB+ |
| Slow investigations | Check LLM endpoint configuration in `.env` |
