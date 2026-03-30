"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 9: bloodhound + inventory_scan evasion + phantom IPs
    return {
        "task_type": "inventory_scan",
        "severity": "info",
        "siem_event": {
            "title": "Asset Inventory Scan",
            "source_ip": "192.168.50.10",
            "destination_ip": "192.168.50.20",
            "username": "svc_inventory",
            "hostname": "inventory-srv",
            "rule_name": "AssetDiscovery",
            "raw_log": (
                "EventID=4688 Process=SharpHound.exe "
                "CommandLine=bloodhound --CollectionMethod All --Domain corp.local "
                "User=svc_inventory ParentProcess=cmd.exe "
                "OutputFile=C:\\temp\\corp_bloodhound.zip"
            ),
        },
    }
