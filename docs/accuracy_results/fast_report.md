# HYDRA Accuracy Report — fast tier

**Generated:** 2026-03-16T14:39:24Z
**Corpus:** 70 labeled alerts
**Model tier:** fast

## Summary

| Metric | Value |
|--------|-------|
| Overall accuracy (verdict) | 100.0% |
| False positive rate | 0.0% |
| False negative rate | 0.0% |
| Code generation success | 100.0% |
| Risk score in range | 100.0% |
| Mean risk score error | 0.0 |
| IOC F1 score | 0.000 |
| Hallucination rate | 0.0% |
| Mean investigation time | 0ms |

## Accuracy by Category

| Category | Total | Accuracy | Code Success | IOC F1 |
|----------|-------|----------|-------------|--------|
| brute_force | 9 | 100.0% | 100.0% | 0.000 |
| c2 | 4 | 100.0% | 100.0% | 0.000 |
| c2_beacon | 5 | 100.0% | 100.0% | 0.000 |
| data_exfiltration | 5 | 100.0% | 100.0% | 0.000 |
| defense_evasion | 5 | 100.0% | 100.0% | 0.000 |
| lateral_movement | 9 | 100.0% | 100.0% | 0.000 |
| malware | 5 | 100.0% | 100.0% | 0.000 |
| persistence | 5 | 100.0% | 100.0% | 0.000 |
| phishing | 9 | 100.0% | 100.0% | 0.000 |
| privilege_escalation | 5 | 100.0% | 100.0% | 0.000 |
| ransomware | 4 | 100.0% | 100.0% | 0.000 |
| reconnaissance | 5 | 100.0% | 100.0% | 0.000 |

## Accuracy by Difficulty

| Difficulty | Total | Accuracy |
|------------|-------|----------|
| clean | 5 | 100.0% |
| easy | 5 | 100.0% |
| hard | 5 | 100.0% |
| multi_attack | 5 | 100.0% |
| n/a | 50 | 100.0% |

## Individual Results

| Alert | Category | Difficulty | Verdict | Risk | IOC F1 | Code OK |
|-------|----------|------------|---------|------|--------|--------|
| brute_force-easy | brute_force | easy | correct | 65 | 0.00 | yes |
| brute_force-hard | brute_force | hard | correct | 60 | 0.00 | yes |
| brute_force-multi_attack | brute_force | multi_attack | correct | 70 | 0.00 | yes |
| brute_force-clean | brute_force | clean | correct | 7 | 0.00 | yes |
| c2-easy | c2 | easy | correct | 65 | 0.00 | yes |
| c2-hard | c2 | hard | correct | 60 | 0.00 | yes |
| c2-multi_attack | c2 | multi_attack | correct | 70 | 0.00 | yes |
| c2-clean | c2 | clean | correct | 7 | 0.00 | yes |
| lateral_movement-easy | lateral_movement | easy | correct | 65 | 0.00 | yes |
| lateral_movement-hard | lateral_movement | hard | correct | 60 | 0.00 | yes |
| lateral_movement-multi_attack | lateral_movement | multi_attack | correct | 70 | 0.00 | yes |
| lateral_movement-clean | lateral_movement | clean | correct | 7 | 0.00 | yes |
| phishing-easy | phishing | easy | correct | 65 | 0.00 | yes |
| phishing-hard | phishing | hard | correct | 60 | 0.00 | yes |
| phishing-multi_attack | phishing | multi_attack | correct | 70 | 0.00 | yes |
| phishing-clean | phishing | clean | correct | 7 | 0.00 | yes |
| ransomware-easy | ransomware | easy | correct | 65 | 0.00 | yes |
| ransomware-hard | ransomware | hard | correct | 60 | 0.00 | yes |
| ransomware-multi_attack | ransomware | multi_attack | correct | 70 | 0.00 | yes |
| ransomware-clean | ransomware | clean | correct | 7 | 0.00 | yes |
| TP-001 | c2_beacon | n/a | correct | 85 | 0.00 | yes |
| TP-002 | c2_beacon | n/a | correct | 85 | 0.00 | yes |
| TP-003 | c2_beacon | n/a | correct | 80 | 0.00 | yes |
| FP-001 | c2_beacon | n/a | correct | 15 | 0.00 | yes |
| FP-002 | c2_beacon | n/a | correct | 10 | 0.00 | yes |
| TP-004 | brute_force | n/a | correct | 90 | 0.00 | yes |
| TP-005 | brute_force | n/a | correct | 80 | 0.00 | yes |
| TP-006 | brute_force | n/a | correct | 80 | 0.00 | yes |
| FP-003 | brute_force | n/a | correct | 15 | 0.00 | yes |
| FP-004 | brute_force | n/a | correct | 10 | 0.00 | yes |
| TP-007 | phishing | n/a | correct | 90 | 0.00 | yes |
| TP-008 | phishing | n/a | correct | 80 | 0.00 | yes |
| TP-009 | phishing | n/a | correct | 80 | 0.00 | yes |
| FP-005 | phishing | n/a | correct | 15 | 0.00 | yes |
| FP-006 | phishing | n/a | correct | 10 | 0.00 | yes |
| TP-010 | lateral_movement | n/a | correct | 90 | 0.00 | yes |
| TP-011 | lateral_movement | n/a | correct | 90 | 0.00 | yes |
| TP-012 | lateral_movement | n/a | correct | 80 | 0.00 | yes |
| FP-007 | lateral_movement | n/a | correct | 15 | 0.00 | yes |
| FP-008 | lateral_movement | n/a | correct | 10 | 0.00 | yes |
| TP-013 | malware | n/a | correct | 90 | 0.00 | yes |
| TP-014 | malware | n/a | correct | 90 | 0.00 | yes |
| TP-015 | malware | n/a | correct | 80 | 0.00 | yes |
| FP-009 | malware | n/a | correct | 15 | 0.00 | yes |
| FP-010 | malware | n/a | correct | 10 | 0.00 | yes |
| TP-016 | data_exfiltration | n/a | correct | 90 | 0.00 | yes |
| TP-017 | data_exfiltration | n/a | correct | 80 | 0.00 | yes |
| FP-011 | data_exfiltration | n/a | correct | 15 | 0.00 | yes |
| FP-012 | data_exfiltration | n/a | correct | 10 | 0.00 | yes |
| FP-013 | data_exfiltration | n/a | correct | 10 | 0.00 | yes |
| TP-018 | privilege_escalation | n/a | correct | 90 | 0.00 | yes |
| TP-019 | privilege_escalation | n/a | correct | 90 | 0.00 | yes |
| FP-014 | privilege_escalation | n/a | correct | 15 | 0.00 | yes |
| FP-015 | privilege_escalation | n/a | correct | 10 | 0.00 | yes |
| FP-016 | privilege_escalation | n/a | correct | 10 | 0.00 | yes |
| TP-020 | reconnaissance | n/a | correct | 80 | 0.00 | yes |
| TP-021 | reconnaissance | n/a | correct | 80 | 0.00 | yes |
| FP-017 | reconnaissance | n/a | correct | 15 | 0.00 | yes |
| FP-018 | reconnaissance | n/a | correct | 10 | 0.00 | yes |
| FP-019 | reconnaissance | n/a | correct | 10 | 0.00 | yes |
| TP-022 | persistence | n/a | correct | 90 | 0.00 | yes |
| TP-023 | persistence | n/a | correct | 80 | 0.00 | yes |
| FP-020 | persistence | n/a | correct | 15 | 0.00 | yes |
| FP-021 | persistence | n/a | correct | 10 | 0.00 | yes |
| FP-022 | persistence | n/a | correct | 10 | 0.00 | yes |
| TP-024 | defense_evasion | n/a | correct | 90 | 0.00 | yes |
| TP-025 | defense_evasion | n/a | correct | 90 | 0.00 | yes |
| FP-023 | defense_evasion | n/a | correct | 15 | 0.00 | yes |
| FP-024 | defense_evasion | n/a | correct | 10 | 0.00 | yes |
| FP-025 | defense_evasion | n/a | correct | 10 | 0.00 | yes |
