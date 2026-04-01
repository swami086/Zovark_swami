import sys, json
sys.path.insert(0, 'C:\\Users\\vinay\\Desktop\\HYDRA\\hydra-mvp\\worker')
from tools.runner import execute_plan

plans = json.load(open('C:\\Users\\vinay\\Desktop\\HYDRA\\hydra-mvp\\worker\\tools\\investigation_plans.json'))

# Lateral movement
plan = plans['lateral_movement_detection']['plan']
siem = {
    'source_ip': '10.0.0.1',
    'username': 'admin',
    'raw_log': 'psexec connecting to \\ADMIN$ remote execution pass-the-hash admin share',
    'failed_count': 10,
    'unique_sources': 1,
    'timespan_minutes': 10
}
result = execute_plan(plan, siem, {}, {})
print(f'lateral_movement_detection: {result["risk_score"]} {result["verdict"]}')

# Phishing
plan = plans['phishing_investigation']['plan']
siem = {
    'source_ip': '10.0.0.1',
    'username': 'admin',
    'raw_log': 'From: security@secure-login-update.com Subject: Urgent verify your account before suspend click here secure login password credential',
    'failed_count': 10,
    'unique_sources': 1,
    'timespan_minutes': 10
}
result = execute_plan(plan, siem, {}, {})
print(f'phishing_investigation: {result["risk_score"]} {result["verdict"]}')
for f in result.get('findings', []):
    print(f'  finding: {f}')
for i in result.get('iocs', []):
    print(f'  ioc: {i}')
