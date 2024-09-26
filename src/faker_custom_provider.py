import random

from faker.providers import BaseProvider


class CustomProvider(BaseProvider):

    subject_word_list = [
        "test",
        "testing",
        "incident",
        "cyflare",
        "notification",
        "issue",
        "ticket",
        "alarm",
        "alert",
        "low",
        "high",
        "detection",
        "system",
        "threat",
        "reports",
        "account",
        "new",
        "client",
        "provisioning",
        "removed",
        "escalation",
        "connection",
        "command",
        "configuration",
        "changed",
        "employee",
        "anomalously",
        "connection",
        "attacker",
    ]

    def username(self):
        return random.choice(
            [
                "4i486ily",
                "kqwa0ssn",
                "l7j4ous0",
                "b6z2jzqc",
                "p8zfr4v4",
                "6wlv59y5",
                "bxikma3p",
                "bl7p6ew2",
                "6p6reiy3",
                "gt8vxo99",
                "zi0mvs6u",
                "8c49uwls",
                "u3omf61f",
                "k2shnsnm",
                "j0wr5856",
                "ptolucu1",
                "u4dkaisu",
                "gmchqidj",
                "k1ul856j",
                "t9ebx1g0",
                "teuppgg4",
                "m8e8wiaa",
                "uwwzw93n",
                "p390b7dn",
                "rtp6cjlb",
                "bcamj1q2",
                "22beuv1i",
                "09evwf6c",
                "tybhle1u",
                "9dhh0uhd",
                "pxey5r1n",
                "ob0pza99",
                "l1fbhs07",
                "ff7xz6eu",
                "nh6xr9m3",
                "vw1bouxe",
                "kirc5gs4",
                "to1giywf",
                "wr8coajr",
                "62qsjfht",
                "ltkjhden",
                "vru1zlgb",
                "5s37729v",
                "t32jwttr",
                "q47n6iul",
                "96akipom",
                "szkckay2",
                "0p2poozw",
                "60j68f9x",
                "k92x9syk",
            ]
        )

    def department_name(self):
        return random.choice(
            [
                "CSM",
                "SOAR Platform Team",
                "CyFlare IT",
                "ONE",
                "CyFlare SOC",
                "Assure Team",
                "CyFlare Support",
                "Finance",
                "HR",
                "PMO",
                "Tech Ops",
                "SOC Platform Management",
                "Deployments",
                "SOC Incidents",
            ]
        )

    def ticket_status(self):
        return random.choice(
            [
                "FP - Inaccurate IP Location",
                "TP - Malicious Connection",
                "TP - Whitelisted",
                "Awaiting SOC Reply",
                "FP - Solution Tuning Implemented",
                "UK - Ticket Closed Due to No-Reply",
                "Awaiting Customer Reply",
                "TP - Client Allowed Activity",
                "TP - Solution Tuning Implemented",
                "TP - Confirmed Incident",
                "TP - Pen Testing Activity Complete",
                "TP - Malicious Intent",
                "FP - Normal Behavior",
                "UK - Auto Closure - No Response from Client",
                "On Hold - Awaiting Vendor Support",
                "FP - Inaccurate Detection",
                "UK - Approved to Close - Unknown Outcome",
                "UK - Client Closed Ticket",
                "TP - Blacklisted",
                "CI - Credentials Exposed",
                "TP - Low Priority Incident",
                "FP - Not Malicious",
                "UK - Duplicate Alarm",
                "FP - Confirmed FP by Client",
                "TP - No Action Needed",
            ]
        )

    def priority(self):
        return random.choice(
            [
                "None",
                "Medium",
                "Low",
                "High",
                "Informative",
                "Severe",
                "Unknown",
                "Critical",
            ]
        )

    def channel(self):
        return random.choice(["Facebook", "Web", "Email", "Chat", "Phone"])

    def category(self):
        return random.choice(
            [
                "Defects",
                "None",
                "Potential Information Leak",
                "Upgrade Request",
                "Network Activity",
                "Phishing",
                "Service or SaaS Related",
                "Credential Related",
                "Network Related",
                "Scanning Related",
                "Suspicious Activity",
                "Add/Move/Change",
                "Machine Related",
                "Account Related",
                "Issue/Problem",
                "General",
            ]
        )

    def sub_category(self):
        return random.choice(
            [
                "Account Manipulation",
                "Suspicious Activity",
                "Software Uninstalled",
                "Sensor Connectivity",
                "User Activity/Manipulation",
                "Scanning Activity",
                "Brute Force Activity",
                "Mimikatz Detection",
                "Remote Access Trojan",
                "Execution Activity",
                "Process Related Activity",
                "Malware Identified",
                "Software Installed",
                "Malware IoC",
                "Policy Related",
                "SaaS Application Software",
                "Suspicious Behavior",
                "User Accounts",
                "Anomalous User Behavior",
                "Firewall Connectivity",
                "Account Change Made",
                "Hardware Related",
                "URL Phishing",
                "Sub General",
                "Syslog Ingestion",
            ]
        )

    def yes_no(self):
        return random.choice(["Yes", "No"])

    def classifications(self):
        return random.choice(
            [
                "Implementation",
                "Security Incident",
                "Request",
                "Question",
                "Duplicate",
                "Commercial Change Request",
                "Incident",
                "SOC2",
                "Other",
                "None",
                "Purchasing Requests",
                "Non-Response Cyflare Escalation",
                "Solution Requests",
                "Cyflare Internal - IT",
                "Change Request",
                "Spam",
                "OffBoarding Client",
                "Feature",
                "Service Escalation",
                "Feature",
                "Provisioning",
                "Termination",
                "Security Event",
                "Upgrade Request",
                "Feature Request",
                "ONE Provisioning",
                "Deployment Related",
                "Problem",
                "Corporate Change Request",
                "Staff Onboard",
                "Logs Related",
                "Questions",
                "Report",
                "Issue/Problem",
            ]
        )

    def resolution(self):
        return random.choice(
            [
                "Not active accounts",
                "Rogue SSID",
                "Appliances were reachable",
                "Kickoff call scheduled",
                "Reconnected",
                "Email sent",
                "The NIC was disconnected",
                "False positive",
                "Initial contact made",
                "Initial meeting complete",
                "Successfully added",
                "Testing",
                "Deal not closed",
                "Duplicated ticket",
                "Resolved",
                "IP Blocked",
                "Customer confirmed legitimate access",
                "Client aware of the issue",
                "Traffic blocked",
                "Hotspot",
            ]
        )

    def happiness_rating(self):
        return random.choice(["Bad", "Okay", "Good"])

    def shift_ticket_creation(self):
        return random.choice(["Morning Open", "Afternoon Open", "After Hours Open"])

    def ticket_touches(self):
        return random.choice(["One Touch", "Multi Touch"])

    def status(self):
        return random.choice(["Completed", "In Progress"])

    def case_status(self):
        return random.choice(["Resolved", "In Progress"])

    def age_tier(self):
        return random.choice(
            [
                "0 - 15 Days",
                "16 - 30 Days",
                "31 - 45 Days",
                "46 - 60 Days",
                "Over 60 Days",
            ]
        )

    def first_reply_age_tier(self):
        return random.choice(
            [
                "0 - 2 Hours",
                "2 - 5 Hours",
                "5 - 8 Hours",
                "8 - 12 Hours",
                "12 - 24 Hours",
                "Above 24 Hours",
            ]
        )

    def completion_age_tier(self):
        return random.choice(
            [
                "0 - 6 Hours",
                "6 - 12 Hours",
                "12 - 24 Hours",
                "24 - 48 Hours",
                "Above 48 Hours",
                "Not Resolved",
            ]
        )

    def ticket_handling_mode(self):
        return random.choice(["Overdue", "In Time", "Ongoing"])

    def sla_name(self):
        return random.choice(
            [
                "Essential Support Level",
                "Enhanced Support Level",
                "Priority-based SLAs",
                "Notify Customer - Priority High",
            ]
        )

    def sla_violation_type(self):
        return random.choice(
            [
                "Response and Resolution Violation",
                "Resolution Violation",
                "Not Violated",
                "Response Violation",
            ]
        )

    def cyflare_incident_notification(self):
        return random.choice(["Incident 1", None])

    def severity(self):
        return random.choice(
            ["High", "Low", "Medium", "Normal", "Critical", "Informative", None]
        )

    def associated_indicators_of_compromise(self):
        return random.choice(
            [
                "N/A",
                "ACTION & EXFILTRATION - BRUTE FORCED ATTACK",
                "ACTION & EXFILTRATION - SYN FLOOD ATTACK",
                "ACTION & EXFILTRATION - CRYPTOJACKING",
                "ACTION & EXFILTRATION - MIMIKATZ MEMORY DUMP",
                "ACTION & EXFILTRATION - DNS TUNNELING",
                "FILE SANDBOXED",
                "1075.exe",
                "DELIVERY - MALWARE ACTIVITY",
                "DELIVERY - SPYWARE ACTIVITY",
                "EXPLOITATION - PUBLIC-PRIVATE EXPLOIT ATTEMPTS",
                "MALWARE FAMILY",
                "DELIVERY - TROJAN ACTIVITY",
                "Source IP's",
                "Scanner Reputation",
                "OTX IOC",
                "Files delivered to the spam filter",
                "COMMAND & CONTROL - DGA DETECTED - DGA RESOLVED",
                "SYSTEM COMPROMISE",
                "Originated from a Different Country",
                "Vulnerable Software Exploitation",
                "Potential Command and Control connections",
                "SYSTEM COMPROMISE - WORM INFECTION",
                "Possible bitcoin related",
                "MISC MALWARE - FILE SANDBOXED",
                "Windows Login Events",
                "Potentially Bad Traffic",
                "URL Reconnaissance",
            ]
        )

    def recommended_remediation_actions(self):
        return random.choice(
            [
                "Block IPs",
                "Investigate further",
                "Scan assets",
                "Confirm",
                "Verify",
                "Validate activity",
                "In progress/Investigating",
                "Identify compromised user account",
                "Verify attacks successful",
                "Ensure all data is transmitted",
                "Patch all Windows servers",
                "Isolate system from network",
                "Update Internet Explorer",
                "Check for incorrect password",
                "Quarantine the infected system",
                "N/A",
                "Validate root cause",
                "Verify if the login activity was legitimate",
                "Change passwords immediately",
                "Ensure strong configuration settings",
            ]
        )

    def issue_type(self):
        return random.choice(
            [
                "BDS Exploitation",
                "Delivery",
                "Reconnaissance and Probing",
                "BDS Actions and Exfil",
                "C2",
                "Tuning Request",
                "Network Anomaly",
                "Environmental Awareness",
                "Dashboard/Report Request",
                "Knowledge Transfer or Training Related",
                "Billing or Account Related",
                "Other",
                "Malicious Connection",
                "Duplicate Ticket from Customer Ticket Portal",
                "Reporting",
                "Machine Compromise",
                "Malware Identified",
                "Exploitation and Installation",
                "Reconn",
                "BDS Installation",
                "Potential Phish Email",
                "Appliance Disconnect",
                "Suspicious Behavior",
                "Other/Change",
                "Custom Detection Request",
                "Potential Information Leak",
                "Incident Investigation Request",
                "Deployment Related",
                "Delivery and Attack",
                "Installation",
            ]
        )

    def method(self):
        return random.choice(
            [
                "Traffic Anomaly",
                "Hacking Tool",
                "Memory corruption",
                "Scanner Reputations",
                "Bad Destination reputation",
                "DNS TUNNELING",
                "Malware Infection",
                "Possible Bitcoin Related Connections",
                "Log clear",
                "FILE SANDBOXED",
                "SMB Failures",
                "Logins Failed",
                "Defense Evasion",
                "URL Reconnaissance Anomaly",
                "Anomalous User Activity",
                "DELIVERY – MALWARE ACTIVITY",
                "SYSTEM COMPROMISE - CODE EXECUTION",
                "COMMAND & CONTROL – SERVER COMMANDS",
                "Logon Failure",
                "Cisco Meraki - Rogue SSID",
                "Private to Public Exploit Anomaly",
                "Brute Forced Successful Logins",
                "Tuning/To Review",
                "DNS Request Query to Open DNS",
                "EXPLOITATION - PROCESS ANOMALY",
                "Traffic Anomaly - Bad connection",
                "Malicious Auto Generated Domain Queries" "N/A",
                "Sensor Disconnect and Port Mirroring",
                "TROJAN ACTIVITY DETECTED",
                "Scanner",
                "Cryptojacking",
                "Auto Generated Domain" "Question",
                "Kerberos Authentication Service",
                "Anonymous login",
                "Changed password",
                "Network Activity From msiexec",
                "Suspicious User-agent detected",
                "SYSTEM COMPROMISE - WORM INFECTION",
                "High Number of Failed logins",
                "Possible IIS Integer Overflow DoS",
                "OTX Indicators of Compromise",
                "Anomalous SSH Access Process",
                "Credentials Stolen - Public or Private Breach",
                "Windows PSExec Service Usage",
                "Alert",
                "Suspicious EXE Download",
                "Defense Evasion - Cover Tracks",
            ]
        )

    def ticket_type(self):
        return random.choice(["None", "Inbound", "Outbound"])

    def ticket_source(self):
        return random.choice(
            [
                "None",
                "Microsoft Defender",
                "Recorded Future",
                "Proofpoint Essentials",
                "XDRaaS",
                "SentinelOne",
                "ALienVault",
                "ONE",
                "Exchange",
                "Nessus Pro",
                "CYRISMA",
                "Stellar Cyber",
                "Tenable.io",
                "Rapid7",
                "Sophos Central",
                "Azure Sentinel",
                "Stellar Sensor Down",
            ]
        )

    def ticket_final_outcome_result(self):
        return random.choice(["Uncategorized", "FP", "UK", "TP", "PT"])

    def case_source(self):
        return random.choice(
            [
                "AlienVault",
                "CrowdStrike Falcon",
                "SentinelOne",
                "Sophos Central",
                "Stellar Cyber",
            ]
        )

    def event_name(self):
        return random.choice(
            [
                "$$DELETEMEAPPXDEPLOYMENTCLIENT.DLL5900000D843EC1A",
                "$$DELETEMESYSMAIN.DLLE4298B03D13D010000147CC851",
                "$R009GAR.EXE",
                "02-09-24.EXE",
                "02C1F172EDDBE96F5C4E058F98ACCA5B_FILEHIDER_SMBWORMWMI.EXE",
                "2024 JULY OMD CQI REPORT.DOCX",
                "ADVANCED_PORT_SCANNER_2.5.3869.EXE",
                "ANOMALOUS_FILE_ACTION",
                "ASTDLL.DLL",
                "BAD_REPUTATION_LOGIN",
                "BROWSER.EXE",
                "CLOUD_ACCOUNT_LOGIN_FAILURE_OKTA",
                "CMD.EXE (CLI DC17)",
                "CUSTOM_GOOGLE_WORKSPACE_SUSPEND_USER",
                "custom_O365 - Email Sending Limit Exceeded",
                "DOWNLOADMANAGERSETUP.EXE",
                "DWHFC9A.EXE",
                "ENVIRONMENTAL AWARENESS_SYSTEM ERROR_WINDOWS UPDATE PROCESS FAILURE",
                "EXPLOIT_ATTEMPT_PUB_PRIV",
                "EXTERNAL_RANSOMWARE",
                "FIREFOX_SETUP_19.0.2.EXE",
                "INTERNAL_MALWARE_ACTIVITY",
                "IPSCAN.EXE",
                "KNOWN MALWARE",
                "LGHUB_UPDATER",
                "LOGINITEMS",
                "LOGMEIN.MSI",
                "MICROSOFT_365-COLLECTION-EMAIL_COLLECTION",
                "NETWORKMANAGER.EXE",
                "OFFICE365_OUTSIDE_ENTITY_FILE_SHARING",
                "ONEDRIVE.EXE",
                "PDFCMD.EXE",
                "POWERSHELL.EXE (CLI 0134)",
                "REBOOT.EXE",
                "REPORTVIEW.EXE",
                "RSTUDIO.EXE",
                "SCREENREC.EXE",
                "SENTINELONE-IMPACT-DATA_ENCRYPTED_FOR_IMPACT",
                "SETUP1.EXE",
                "SUSPICIOUS ACTIVITY",
                "SUSPICIOUS_AZURE_DEVICE_ACTIVITY",
                "SYSTEMBACKUP.EXE",
                "TEAMVIEWER.EXE (INTERACTIVE SESSION)",
                "UNICOREANTIVIRUS",
                "UNINSTALL.EXE",
                "UPDATER.EXE",
                "VIEWER.LNK",
                "WEBCOMPANION.DLL",
                "ZOOM.EXE",
                "ZOOMINSTALLERFULL.EXE",
            ]
        )

    def closure_reason(self):
        return random.choice(
            [
                "Authorized activity by client",
                "Authorized country",
                "Auto-Closure Whitelisted Detection",
                "Benign detection",
                "Benign thread intelligence",
                "Detection is blacklisted by SOC",
                "Detection is whitelisted by SOC",
                "Duplicate Alarm",
                "External attack",
                "False Positive",
                "Invalid Detection by Tool",
                "Known Activity",
                "Known and authorized process",
                "Known internal application activity",
                "Known security tool activity",
                "Known service related detection",
                "Malware",
                "Muted Detection - Operational",
                "Normal behavior",
                "Other",
                "Penetration test",
                "Potential/confirmed incident by SOC",
                "Priority is low",
                "Rule under construction",
                "Scheduled task activity",
                "Similar case is already under investigation",
                "System blocked the attack",
                "Valid accounts",
                "Whitelisted activity based on SOC survey",
                "Whitelisted IP address",
                "Whitelisted network scanner",
                "Whitelisted vulnerability scanner",
            ]
        )

    def ti_reputation(self):
        return random.choice(["Benign"])

    def case_tag(self):
        return random.choice(["Maintenance", "Malicious", "Not malicious"])

    def sip_dip_reputation(self):
        return random.choice(
            [
                "Blackhole",
                "Bot",
                "Brute_Forcer",
                "CnC",
                "Compromised",
                "DDoSAttacker",
                "DDoSTarget",
                "DGA_CnC",
                "emerging_thread",
                "Good",
                "Malicious",
                "Mobile_CnC" "Malware",
                "Phishing",
                "Scanner",
                "SpywareCnC" "TorNode",
            ]
        )

    def ip_type(self):
        return random.choice(["private", "public", "unknown", "multicast"])

    def mitre_technique_name(self):
        return random.choice(
            [
                "Abuse Elevation Control Mechanism",
                "Accessibility Features",
                "Access Token Manipulation",
                "Account Access Removal",
                "Account Discovery",
                "Account Manipulation",
                "Active Scanning",
                "Adware",
                "Application Lawyer Protocol",
                "Automated Exfiltration",
                "Boot or Logon Autostart Execution",
                "Brute Force",
                "Command and Scripting Interpreter",
                "Compromise Accounts",
                "Compromise Infrastructure",
                "Create Account",
                "Create or Modify System Process",
                "Credentials from Password Stores",
                "Custom Command and Control Protocol",
                "Data Destruction",
                "Data Encrypted for Impact",
                "Data from Cloud Storage Object",
                "Data from Network Shared Drive",
                "Data Manipulation",
                "Data Staged",
                "Data Transfer Size Limits",
                "Disable or Modify Tools",
                "Domain Policy Modification",
                "Drive-by Compromise",
                "Dynamic Resolution",
                "Email Collection",
                "Encrypted Channel",
                "Event Triggered Execution",
                "Execution Guardrails",
                "Exfiltration Over Alternative Protocol",
                "Exfiltration Over Web Service",
                "Exploitation Over Web Service",
                "Exploitation for Credential Access",
                "Exploitation for Privilege Escalation",
                "Exploitation of Remote Services",
                "Exploit Public-Facing Application",
                "External Remote Services",
                "Forced Authentication",
                "Forge Web Credentials",
                "Hijack Execution Flow",
                "Impair Defenses",
                "Inhibit System Recovery",
                "Input Capture",
                "Man-in-the-Middle",
                "Masquerading",
                "Modify Authentication Process",
                "Network Denial of Service",
                "Network Service Scanning",
                "OS Credential Dumping",
                "Permission Groups Discovery",
                "Phishing",
                "PowerShell",
                "Protocol Tunneling",
                "Proxy",
                "Query Registry",
                "Remote Access Software",
                "Remote Services",
                "Rootkit",
                "Scheduled Task/Job",
                "Service Stop",
                "System Information Discovery",
                "System Network Configuration Discovery",
                "Traffic Signaling",
                "Transfer Data to Cloud Account",
                "Use Alternate Authentication Material",
                "User Execution",
                "Valid Accounts",
                "Windows Management Instrumentation",
                "XDR Account Anomaly",
                "XDR Bad Reputation",
                "XDR Command and Control Connection Exploitation",
                "XDR Endpoint Indicator of Threat",
                "XDR Exploited Vulnerability",
                "XDR Location Anomaly",
                "XDR Rule Violation",
                "XDR Spyware",
                "XDR Threat Intelligence",
                "XDR Trojan",
                "XDR User Agent Anomaly",
            ]
        )

    def mitre_sub_technique_name(self):
        return random.choice(
            ["Domain Generation Algorithms", "Password Spraying", "Still Working"]
        )

    def mitre_tactic(self):
        return random.choice(
            [
                "Collection",
                "Command and Control",
                "Credential Access",
                "Defense Evasion",
                "Discovery",
                "Execution",
                "Exfiltration",
                "Impact",
                "Initial Access",
                "Lateral Movement",
                "Machine Learning",
                "Malware",
                "Persistence",
                "Persistence, Privilege Escalation",
                "Privilege Escalation",
                "Reconnaissance",
                "Resource Development",
                "XDR EBA",
                "XDR Intel",
                "XDR Malware",
                "XDR NBA",
                "XDR UBA",
            ]
        )

    def mitre_technique_id(self):
        return random.choice(
            [
                "CST0006",
                "CST0013",
                "CST0014",
                "T1003",
                "T1012",
                "T1014",
                "T1016",
                "T1018",
                "T1020",
                "T1021",
                "T1027",
                "T1029",
                "T1030",
                "T1068",
                "T1069",
                "T1070",
                "T1531",
                "T1537",
                "T1543",
                "T1546",
                "T1547",
                "XT1000",
                "XT1003",
                "XT1004",
                "XT2001",
                "XT2002",
                "XT2003",
                "XT2004",
            ]
        )

    def mitre_tactic_id(self):
        return random.choice(
            [
                "CSTA0001",
                "CSTA0004",
                "T1095",
                "T1187",
                "TA0001",
                "TA0002",
                "TA0003",
                "TA0004",
                "TA0005",
                "TA0006",
                "TA0007",
                "XTA0001",
                "XTA0006",
            ]
        )

    def s1_site_name(self):
        return random.choice(
            [
                "CareerServices",
                "ClarkAcademy",
                "Default-First-Site-Name",
                "Default-Site-Link",
                "HS-MS",
                "LHRIC",
                "LHRIC-NOC",
                "Parrot",
                "PEARLRIVER",
                "RyeLake",
                "WAVERLY",
                "Woodlands",
            ]
        )

    def xdr_event_category(self):
        return random.choice(
            [
                "AccessGovernance",
                "DataGovernance",
                "DataLossPrevention",
                "Killchain",
                "MailFlow",
                "Network",
                "Other",
                "Supervision",
                "ThreatManagement",
            ]
        )

    def xdr_msg_class(self):
        return random.choice(
            [
                "audit-rule",
                "aws_cloudwatch_waf",
                "aws_guardduty_finding",
                "azure_activity_log",
                "azure_ad_audit",
                "azure_ad_risk_detection",
                "azure_ad_signin",
                "box_events",
                "ciscoumbrella_dnslogs",
                "cloudtrail",
                "crowdstrike_detection_summary",
                "Darktrace",
                "dhcp",
                "duosecurity_administrator",
                "duosecurity_authentication",
                "firewall",
                "First Due sFTP Connector",
                "forti_analyzer",
                "gsuite",
                "ids_event",
                "interflow_traffic",
                "ips",
                "jumpcloud_directoryinsights",
                "mcafee",
                "microsoft_defender_alerts",
                "Microsoft-Windows-PowerShell",
                "Microsoft-Windows-Security-Auditing",
                "Microsoft-Windows-Windows Defender",
                "mimecast_email",
                "mimecast_email_url_protect_log",
                "MSSQLSERVER",
                "netflow",
                "office365_audit_azureactivedirectory",
                "office365_audit_general",
                "office365_audit_sharepoint",
                "okta",
                "salesforce_LoginHistory",
                "sentinelone_threat_detection",
                "sophos_alerts",
                "sophos_events",
                "user-login",
                "vpcflow",
                "windows_traffic",
            ]
        )

    def xdr_msg_origin_source(self):
        return random.choice(
            [
                "aws_cloudwatch",
                "aws_guardduty",
                "azure_ad",
                "box_content_cloud",
                "ciscoumbrella",
                "cloudtrail",
                "crowdstrike",
                "Darktrace",
                "dhcp",
                "dhcpd",
                "duosecurity",
                "forti_analyzer",
                "fw_checkpoint",
                "fw_cisco_asa",
                "fw_fortigate",
                "fw_palo_alto",
                "fw_sophos",
                "gsuite",
                "ips_fire_power",
                "jumpcloud_directory_insights",
                "linux_agent",
                "mcafee",
                "meraki",
                "microsoft_azure",
                "microsoft_defender",
                "mimecast_email",
                "modular_sensor",
                "netflow",
                "netflowipfix",
                "network_sensor",
                "office365",
                "okta",
                "ordr_cds",
                "pfsense_fw",
                "proofpoint_tap",
                "salesforce",
                "security_sensor",
                "sensor",
                "sentinelone_endpoint",
                "sonicfw",
                "sophos_alerts",
                "sophos_events",
                "watchguard_fw",
                "windows_agent",
            ]
        )

    def xdr_appid_name(self):
        return random.choice(
            [
                "0" "abcnews",
                "amazon",
                "amazon_aws",
                "amazon_cloud_drive",
                "amazon_music",
                "android_cnxmgr",
                "anydesk",
                "apple",
                "bing",
                "Bitdefender.Update",
                "bittorrent",
                "bmff",
                "box_net",
                "boxnet-uploading",
                "cisco_ucm",
                "Cloudflare-CDN",
                "dhcp",
                "dicom",
                "DNS",
                "dns-base",
                "domain",
                "dropbox",
                "echo-tcp",
                "Edgio-CDN",
                "elasticsearch",
                "enip",
                "epm",
                "epmap",
                "eth",
                "expedia",
                "facebook",
                "fast_com",
                "fastly",
                "filemaker_pro",
                "Filezilla ports",
                "Fortinet-FortiGuard",
                "foxnews",
                "ftp",
                "gcm",
                "gmail",
                "google-base",
                "Google.Chat_Video.Call",
                "google-docs-base",
                "google_messages",
                "google_play",
                "gsuite",
                "http",
                "http2",
                "HTTP-4",
                "http-audio",
                "http_injector",
                "HTTP-proxy",
                "HTTPS",
                "HTTPS-3804",
                "HTTPS-4",
                "HTTPS.BROWSER",
                "icloud",
                "icmp",
                "iheartradio",
                "iiop",
                "imap",
                "imdb",
                "INFO_ADDRESS",
                "instagram",
                "insufficient-data",
                "ip6",
                "ipsec",
                "isakmp",
                "iscsi",
                "jetdirect",
                "kaspersky",
                "kerberos",
                "krb5",
                "lastpass",
                "LDAP",
                "logmein",
                "mapi",
                "microsoft",
                "Microsoft-Azure",
                "microsoft-ds",
                "Microsoft-Office365",
                "Microsoft.Office.Update",
                "Microsoft.Portal",
                "MMS",
                "mount",
                "ms_teams",
                "ms-update",
                "ms-wbt-server",
                "mylife",
                "MYSQL",
                "nbns",
                "NETBIOS",
                "netflow",
                "nfl",
                "nfs",
                "NFSv4",
                "nielsen",
                "norton_update",
                "nspi",
                "ntp",
                "o365_login",
                "ocsp",
                "onedrive",
                "openx",
                "outlook",
                "panos-global-protect",
                "ping",
                "portmap",
                "pptp",
                "qq-base",
                "quic",
                "radius",
                "rdp",
                "redis",
                "ring_central",
                "rollout",
                "rsh",
                "rtcp",
                "rtp",
                "rtsp",
                "SAMBA",
                "samsung_apps",
                "sccm",
                "sharepoint_online",
                "signal_private_messenger",
                "sip",
                "skype",
                "smb",
                "smtp",
                "smtp-base",
                "snapchat",
                "snmp",
                "soap",
                "solarwinds",
                "speedtest",
                "spotify",
                "ssdp",
                "ssh",
                "SSL",
                "steam",
                "syslog",
                "tcp1",
                "tcp_1-1024",
                "tcp/13",
                "tds",
                "TeamViewer",
                "Telegram",
                "telnet",
                "tftp",
                "tokbox",
                "traceroute",
                "twitch",
                "udp1057",
                "unknown",
                "upnp",
                "UPnP",
                "vmware",
                "wb_games",
                "web-browsing",
                "Web Management",
                "websocket",
                "windows_azure",
                "windowslogin",
                "windows_update",
                "wmi",
                "x_vpn",
                "yahoo",
                "youtube",
                "zoom",
            ]
        )

    def xdr_appid_family(self):
        return random.choice(
            [
                "Application",
                "Audio/Video",
                "Authentication",
                "Database",
                "Encrypted",
                "File",
                "Game",
                "Instant",
                "Mail",
                "Middleware",
                "Network",
                "Peer",
                "Printer",
                "Standard",
                "Terminal",
                "Thin",
                "Tunneling",
                "Web",
                "Webmail",
            ]
        )

    def xdr_dstip_reputation_source(self):
        return random.choice(
            [
                "AellaDataCloud",
                "AlienVault",
                "Blacksuit_Ransomware_2024_08",
                "DHS",
                "DHS, ETPro",
                "ETPro",
                "HamsterKombat_Malware_2024_07",
                "JumpCloud_IOC_2023_07",
                "MOVEit_Exploitation",
                "StellarCyber",
            ]
        )

    def xdr_logon_process_name(self):
        return random.choice(
            [
                "Advapi",
                "Authz",
                "C",
                "CredPro",
                "IAS",
                "Kerberos",
                "Negotiat",
                "NtLmSsp",
                "Schannel",
                "User32",
            ]
        )

    def xdr_event_source(self):
        return random.choice(
            [
                "aws_guardduty",
                "azure_ad_risk_detection",
                "correlation",
                "crowdstrike",
                "gsuite_alert",
                "ids",
                "microsoft_365",
                "Microsoft-Windows-Windows Defender",
                "mimecast",
                "ml",
                "ms_defender_atp",
                "new_ml",
                "playbook",
                "proofpoint_tap",
                "rule_detection",
                "sa",
                "sandbox",
                "sentinelone",
                "threat",
            ]
        )

    def xdr_fim_action(self):
        return random.choice(
            ["attributes_modified", "created", "deleted", "moved", "updated"]
        )

    def xdr_ids_category(self):
        return random.choice(
            [
                "Access to a potentially vulnerable web application",
                "A Network Trojan was detected",
                "Attempted Administrator Privilege Gain",
                "Attempted Denial of Service",
                "Attempted Information Leak",
                "Attempted User Privilege Gain",
                "Decode of an RPC Query",
                "Detection of a Denial of Service Attack",
                "Detection of a Network Scan",
                "Exploit-exe exe.MP_131 (Exploit)",
                "Information Leak",
                "Misc activity",
                "Misc Attack",
                "N/A",
                "Not Suspicious Traffic",
                "Potential Corporate Privacy Violation",
                "Potentially Bad Traffic",
                "Successful Administrator Privilege Gain",
                "Successful User Privilege Gain",
                "Targeted Malicious Activity was Detected",
                "Unknown Traffic",
                "Web Application Attack",
                "WEB-ATTACKS Web Application SQL Injection (INSERT INTO) 2",
                "WEB-ATTACKS Web Application XXE Injection 1",
            ]
        )

    def xdr_ids_signature(self):
        return random.choice(
            [
                "Anti-Spyware Prevention Alert",
                "ATTACK_RESPONSE Metasploit",
                "ATTACK_RESPONSE Net User Command Response",
                "CINS Active Threat Intelligence Poor Reputation IP group 1",
                "COMPROMISED Known Compromised or Hostile Host Traffic group 1",
                "Connection Closed",
                "Connection Opened",
                "CURRENT_EVENTS Balada Domain in DNS Lookup (colorschemeas.com)",
                "DNS DNS Lookup for localhost.DOMAIN.TLD",
                "DNS Query for .cc TLD",
                "DNS Query to a *.top domain - Likely Hostile",
                "DOS Possible NTP DDoS Inbound Frequent Un-Authed GET_RESTRICT",
                "DOS Possible SSDP Amplification Scan in Progress",
                "DROP Dshield Block Listed Source group 1",
                "DROP Spamhaus DROP Listed Traffic Inbound group 1",
                "EICAR virus test files detected",
                "ETPRO EXPLOIT Boa HTTPd RCE Attempt",
                "ETPRO MALWARE TakeMyFile User-Agent",
                "ETPRO SCAN Nessus Scanner TFTP Get Attempt",
                "ETPRO TROJAN NetSupport RAT CnC Activity",
                "ETPRO TROJAN Observed Suspicious SSL Cert (testexample)",
                "ETPRO USER_AGENTS Appcelerator Titanium User-Agent Observed",
                "ETPRO WEB_SERVER Microsoft IIS ISAPI Heap Overflow",
                "EXPLOIT Apache Ambari Default Credentials Attempt",
                "EXPLOIT Apache log4j RCE Attempt (http rmi) (CVE-2021-44228)",
                "EXPLOIT Malformed HeartBeat Response",
                "GPL ATTACK_RESPONSE directory listing",
                "GPL DNS zone transfer UDP",
                "GPL IMAP fetch overflow attempt",
                "GPL WEB_SERVER /~root access",
                "IP spoof dropped",
                "IPv6 Packet with extension header received",
                "Malformed or unhandled IP packet dropped",
                "MALWARE-CNC Netfilter rootkit download attempt",
                "OS-OTHER Bash CGI environment variable injection attempt",
                "OS-WINDOWS Microsoft Windows SMB possible leak of kernel heap memory",
                "passwd",
                "POLICY-OTHER Adobe ColdFusion admin interface access attempt",
                "Received packet retransmission. Drop duplicate packet",
                "SCAN Potential SSH Scan",
                "SERVER-APACHE Apache HTTP server SSRF attempt",
                "SERVER-OTHER tcpdump ISAKMP parser buffer overflow attempt",
                "SERVER-WEBAPP Cisco ASA directory traversal attempt",
                "TCP packet dropped",
                "TOR Known Tor Exit Node Traffic group 101",
                "TROJAN Possible WannaCry DNS Lookup 1",
                "USER_AGENTS User-Agent (Internet Explorer)",
                "User logged out - from SSL VPN client client",
                "WEB_CLIENT Obfuscated Javascript // ptth",
                "WEB_SERVER SQL Injection Select Sleep Time Delay",
                "WEB_SPECIFIC_APPS Vulnerable Magento Adminhtml Access",
                "WORM TheMoon.linksys.router 1",
            ]
        )

    def xdr_login_type(self):
        return random.choice(
            [
                "azure_ad",
                "azure_ad_mfa_log",
                "cloudtrail_console",
                "ftp_traffic",
                "gsuite",
                "kerberos_auth",
                "mysql_traffic",
                "o365_log",
                "okta",
                "rdp_log",
                "rdp_traffic",
                "salesforce_Application",
                "salesforce_Remote-Access-2.0",
                "salesforce_Remote-Access-Client",
                "salesforce_SAML-Sfdc-Initiated-SSO",
                "smb_traffic",
                "ssh_log",
                "ssh_traffic",
                "tds_traffic",
                "windows_login",
                "win_interactive_log",
                "win_network_log",
                "win_unlock_log",
            ]
        )

    def ip_address(self):
        return random.choice(
            [
                "52.218.50.65",
                "101.129.203.107",
                "253.93.85.39",
                "109.109.26.186",
                "246.191.87.140",
                "174.60.217.104",
                "24.131.131.120",
                "23.146.62.209",
                "110.112.143.106",
                "218.210.238.179",
                "20.117.227.251",
                "26.57.49.54",
                "0.95.144.115",
                "156.72.37.122",
                "47.48.162.142",
                "61.106.21.174",
                "74.40.31.180",
                "25.213.164.51",
                "121.23.57.82",
                "65.38.135.121",
                "197.38.153.136",
                "255.216.217.222",
                "1.82.101.252",
                "30.7.34.63",
                "176.138.71.24",
                "179.21.105.193",
                "205.114.82.111",
                "181.84.222.183",
                "126.95.205.82",
                "179.152.128.174",
                "210.236.6.5",
                "21.3.56.190",
                "241.90.157.247",
                "169.113.132.51",
                "4.191.104.222",
                "197.0.221.158",
                "222.80.118.36",
                "49.137.111.207",
                "169.0.206.24",
                "195.196.132.189",
                "210.83.35.173",
                "92.75.23.13",
                "166.242.28.226",
                "104.204.165.204",
                "106.254.7.126",
                "57.220.215.234",
                "102.197.228.9",
                "108.236.45.196",
                "85.242.215.218",
                "184.198.151.239",
            ]
        )

    def country_code(self):
        return random.choice(["US", "AU", "CN", "ET", "FR", "IN", "PK", "RU"])
