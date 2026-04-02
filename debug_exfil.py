import sys
sys.path.insert(0, '/app')
from tools.detection import detect_data_exfil

result = detect_data_exfil({'raw_log': 'Multiple failed auth attempts then successful upload to personal drive'})
print('Risk:', result['risk_score'])
print('Findings:', result['findings'])
