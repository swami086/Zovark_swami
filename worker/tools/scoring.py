"""Scoring tools — deterministic risk scoring for attack types."""
import math


def score_brute_force(failed_count: int, unique_sources: int, timespan_minutes: int) -> int:
    """Risk score for brute force attacks. 0-100."""
    # Coerce inputs safely; non-numeric inputs are suspicious and get a safe fallback
    try:
        failed_count = int(failed_count)
    except (ValueError, TypeError):
        failed_count = 0
    try:
        unique_sources = int(unique_sources)
    except (ValueError, TypeError):
        unique_sources = 0
    try:
        timespan_minutes = int(timespan_minutes)
    except (ValueError, TypeError):
        timespan_minutes = 0

    if failed_count <= 0:
        return 5

    score = 0

    # Base score from failure count
    if failed_count >= 500:
        score += 60
    elif failed_count >= 100:
        score += 45
    elif failed_count >= 50:
        score += 35
    elif failed_count >= 10:
        score += 20
    else:
        score += 10

    # Velocity: failures per minute
    if timespan_minutes > 0:
        rate = failed_count / timespan_minutes
        if rate >= 50:
            score += 25
        elif rate >= 10:
            score += 15
        elif rate >= 1:
            score += 5

    # Velocity bonus: extreme volume in short time
    if timespan_minutes > 0:
        rate = failed_count / timespan_minutes
        if failed_count >= 500 and rate >= 50:
            score += 15

    # Multiple sources = credential stuffing
    if unique_sources >= 10:
        score += 15
    elif unique_sources >= 3:
        score += 10

    return min(100, max(0, score))


def score_phishing(url_count: int, suspicious_domains: int, has_credential_form: bool, has_urgency_language: bool) -> int:
    """Risk score for phishing. 0-100."""
    score = 0

    if url_count > 0:
        score += 15
    if suspicious_domains > 0:
        score += min(30, suspicious_domains * 15)
    if has_credential_form:
        score += 30
    if has_urgency_language:
        score += 15

    # Compound indicators
    if suspicious_domains > 0 and has_credential_form:
        score += 10

    return min(100, max(0, score))


def score_lateral_movement(method: str, is_admin_share: bool, is_remote_exec: bool, uses_pass_the_hash: bool) -> int:
    """Risk score for lateral movement. 0-100."""
    score = 0

    # Method-based scoring
    high_risk_methods = {"psexec", "wmic", "wmi", "winrm", "dcom", "smbexec"}
    medium_risk_methods = {"rdp", "ssh", "powershell_remoting", "powershell"}
    method_lower = method.lower() if method else ""

    if method_lower in high_risk_methods:
        score += 40
    elif method_lower in medium_risk_methods:
        score += 25
    else:
        score += 15

    if is_admin_share:
        score += 20
    if is_remote_exec:
        score += 20
    if uses_pass_the_hash:
        score += 25

    return min(100, max(0, score))


def score_exfiltration(bytes_transferred: int, is_external_dest: bool, is_off_hours: bool, is_encrypted: bool) -> int:
    """Risk score for data exfiltration. 0-100."""
    score = 0

    # Volume-based scoring
    gb = bytes_transferred / (1024 * 1024 * 1024)
    mb = bytes_transferred / (1024 * 1024)
    if gb >= 1:
        score += 40
    elif mb >= 100:
        score += 30
    elif mb >= 10:
        score += 20
    elif mb >= 1:
        score += 10
    else:
        score += 5

    if is_external_dest:
        score += 25
    if is_off_hours:
        score += 15
    if is_encrypted:
        score += 15

    # Compound
    if is_external_dest and is_off_hours:
        score += 10

    return min(100, max(0, score))


def score_c2_beacon(interval_stddev: float, avg_interval_seconds: float, connection_count: int, domain_entropy: float) -> int:
    """Risk score for C2 beaconing. 0-100."""
    score = 0

    # Regular interval (low stddev relative to mean)
    if avg_interval_seconds > 0 and interval_stddev >= 0:
        cv = interval_stddev / max(avg_interval_seconds, 0.01)  # coefficient of variation
        if cv < 0.1:
            score += 35  # Very regular
        elif cv < 0.3:
            score += 25
        elif cv < 0.5:
            score += 15

    # Connection count
    if connection_count >= 100:
        score += 25
    elif connection_count >= 50:
        score += 15
    elif connection_count >= 10:
        score += 10

    # Domain entropy (DGA detection)
    if domain_entropy >= 4.0:
        score += 25
    elif domain_entropy >= 3.5:
        score += 15
    elif domain_entropy >= 3.0:
        score += 10

    # Short intervals
    if 0 < avg_interval_seconds <= 60:
        score += 15
    elif avg_interval_seconds <= 300:
        score += 5

    return min(100, max(0, score))


def score_generic(indicators_found: int, high_severity_count: int, medium_severity_count: int) -> int:
    """Generic risk score based on indicator counts and severity. 0-100."""
    score = 0

    # Base from total indicators
    if indicators_found >= 10:
        score += 30
    elif indicators_found >= 5:
        score += 20
    elif indicators_found >= 1:
        score += 10

    # Severity weighting
    score += min(40, high_severity_count * 15)
    score += min(20, medium_severity_count * 5)

    return min(100, max(0, score))
