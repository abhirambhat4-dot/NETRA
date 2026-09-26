import type {
  AuthorizationStatus,
  ContainmentActionType,
  ContainmentStatus,
  DetectionSource,
  IncidentStatus,
  MemoryOutcome,
  Protocol,
  Severity,
} from '@/api/types'

/**
 * Incident scenarios — the single narrative source for the mock world.
 * db.ts expands each scenario into events, a risk assessment, a decision,
 * authorization, containment and cyber-memory records, all cross-linked.
 *
 * Times are minutes before page load.
 */

export interface EventSeed {
  min: number
  source: Exclude<DetectionSource, 'HYBRID'>
  eventType: string
  signature?: string
  protocol: Protocol
  srcPort?: number
  dstPort?: number
  severity: Severity
  anomaly: number // 0–1
}

export interface IncidentScenario {
  id: string
  threatName: string
  description: string
  sourceIp: string
  destinationIp: string
  assetId: string
  mitreTechniqueId: string
  detectionSource: DetectionSource
  status: IncidentStatus
  firstSeenMin: number
  lastSeenMin: number
  /** When containment completed / incident was dismissed. */
  closedMin?: number
  eventCount: number
  /** Risk inputs — asset criticality and CVSS come from the asset itself. */
  risk: { novelty: number; confidence: number; technique: number; intel: number }
  explanation: string[]
  events: EventSeed[]
  response: {
    action: ContainmentActionType
    target: string
    rationale: string
    alternatives: ContainmentActionType[]
    authorization?: {
      status: AuthorizationStatus
      requestedMin: number
      respondedMin?: number
      comment?: string
    }
    containment?: {
      status: ContainmentStatus
      executedMin?: number
      verifiedMin?: number
      result?: string
    }
    memory?: { id: string; outcome: MemoryOutcome; lessons: string; tags: string[]; similar: string[] }
  }
}

export const SCENARIOS: IncidentScenario[] = [
  // ------------------------------------------------------------------ active
  {
    id: 'INC-1042',
    threatName: 'SSH Brute Force',
    description:
      'Sustained SSH authentication failures against the production database from an internal host, cycling privileged usernames.',
    sourceIp: '192.168.1.25',
    destinationIp: '10.0.0.10',
    assetId: 'AST-001',
    mitreTechniqueId: 'T1110',
    detectionSource: 'HYBRID',
    status: 'INVESTIGATING',
    firstSeenMin: 38,
    lastSeenMin: 3,
    eventCount: 248,
    risk: { novelty: 0.87, confidence: 0.94, technique: 0.9, intel: 0.78 },
    explanation: [
      'Critical asset — Production DB holds regulated student and finance records',
      'High CVSS vulnerability present (CVE-2023-39417, CVSS 8.8)',
      'Repeated authentication failures — 248 attempts in 35 minutes',
      'Highly abnormal behaviour — 87% novelty versus 30-day baseline',
      'Known attack technique — MITRE ATT&CK T1110 Brute Force',
      'High confidence detection — Suricata and ML detector agree (94%)',
    ],
    events: [
      { min: 38, source: 'SURICATA', eventType: 'SSH Scan Detected', signature: 'ET SCAN Potential SSH Scan', protocol: 'SSH', srcPort: 51422, dstPort: 22, severity: 'MEDIUM', anomaly: 0.41 },
      { min: 31, source: 'SURICATA', eventType: 'Repeated SSH Login Failures', signature: 'NETRA SSH auth failure threshold exceeded (50/min)', protocol: 'SSH', srcPort: 51490, dstPort: 22, severity: 'HIGH', anomaly: 0.63 },
      { min: 22, source: 'ML_ANOMALY', eventType: 'Anomalous Authentication Rate', protocol: 'SSH', srcPort: 51733, dstPort: 22, severity: 'CRITICAL', anomaly: 0.87 },
      { min: 14, source: 'SURICATA', eventType: 'SSH Brute Force Burst', signature: 'ET SCAN LibSSH Based Frequent SSH Connections Likely BruteForce Attack', protocol: 'SSH', srcPort: 52011, dstPort: 22, severity: 'CRITICAL', anomaly: 0.79 },
      { min: 3, source: 'ML_ANOMALY', eventType: 'Privileged Username Cycling (root, postgres, admin)', protocol: 'SSH', srcPort: 52240, dstPort: 22, severity: 'CRITICAL', anomaly: 0.91 },
    ],
    response: {
      action: 'BLOCK_IP',
      target: '192.168.1.25',
      rationale: 'Block the source IP at the core firewall to stop the authentication attack immediately.',
      alternatives: ['RATE_LIMIT', 'MONITOR'],
    },
  },
  {
    id: 'INC-1041',
    threatName: 'Suspicious PowerShell Execution',
    description:
      'Encoded PowerShell launched from a Word document on an HR workstation, followed by beaconing to a known malicious host.',
    sourceIp: '10.0.30.47',
    destinationIp: '192.0.2.45',
    assetId: 'AST-005',
    mitreTechniqueId: 'T1059',
    detectionSource: 'HYBRID',
    status: 'CONTAINING',
    firstSeenMin: 72,
    lastSeenMin: 18,
    eventCount: 37,
    risk: { novelty: 0.97, confidence: 0.95, technique: 0.95, intel: 0.96 },
    explanation: [
      'Office process spawned encoded PowerShell — classic initial-access chain',
      'Destination 192.0.2.45 is listed on two threat-intelligence feeds',
      'Periodic beaconing detected — 60 s interval, 5% jitter',
      'Host has an unpatched SmartScreen bypass (CVE-2024-21412, CVSS 8.1)',
      'Same host is the source of credential-access activity (INC-1039)',
    ],
    events: [
      { min: 72, source: 'ML_ANOMALY', eventType: 'Unusual Process Chain (winword.exe → powershell.exe)', protocol: 'TCP', severity: 'HIGH', anomaly: 0.88 },
      { min: 70, source: 'SURICATA', eventType: 'Encoded PowerShell Download Cradle', signature: 'ET POLICY PowerShell Invoke-WebRequest Encoded Command', protocol: 'HTTP', srcPort: 49811, dstPort: 80, severity: 'CRITICAL', anomaly: 0.74 },
      { min: 64, source: 'THREAT_INTEL', eventType: 'Known Malicious IP Contacted', signature: 'Feed match: abuse.ch ThreatFox (C2)', protocol: 'HTTPS', srcPort: 49820, dstPort: 443, severity: 'CRITICAL', anomaly: 0.6 },
      { min: 18, source: 'ML_ANOMALY', eventType: 'C2 Beaconing Pattern Detected', protocol: 'HTTPS', srcPort: 50102, dstPort: 443, severity: 'HIGH', anomaly: 0.93 },
    ],
    response: {
      action: 'ISOLATE_HOST',
      target: 'ws-hr-07 (10.0.30.47)',
      rationale: 'Isolate the workstation from the network to cut the C2 channel and stop lateral movement.',
      alternatives: ['BLOCK_IP'],
      authorization: { status: 'APPROVED', requestedMin: 58, respondedMin: 52, comment: 'Approved — HR notified.' },
      containment: { status: 'IN_PROGRESS', executedMin: 6 },
    },
  },
  {
    id: 'INC-1039',
    threatName: 'Credential Access Pattern',
    description:
      'Remote LSASS access and a DCSync replication request against the domain controller from a non-DC workstation.',
    sourceIp: '10.0.30.47',
    destinationIp: '10.0.0.5',
    assetId: 'AST-004',
    mitreTechniqueId: 'T1003',
    detectionSource: 'HYBRID',
    status: 'INVESTIGATING',
    firstSeenMin: 55,
    lastSeenMin: 12,
    eventCount: 19,
    risk: { novelty: 0.62, confidence: 0.82, technique: 0.9, intel: 0.2 },
    explanation: [
      'Critical asset — domain controller holds every credential in the organisation',
      'DCSync request from a workstation is never legitimate',
      'Source host is already compromised (INC-1041)',
      'Known technique — MITRE ATT&CK T1003 OS Credential Dumping',
    ],
    events: [
      { min: 55, source: 'SURICATA', eventType: 'Remote LSASS Memory Access over SMB', signature: 'ET POLICY SMB Remote LSASS Access', protocol: 'SMB', srcPort: 50331, dstPort: 445, severity: 'HIGH', anomaly: 0.58 },
      { min: 41, source: 'ML_ANOMALY', eventType: 'Anomalous Kerberos TGS Request Volume', protocol: 'TCP', srcPort: 50390, dstPort: 88, severity: 'HIGH', anomaly: 0.79 },
      { min: 12, source: 'SURICATA', eventType: 'DCSync Replication from Non-DC Host', signature: 'ET ATTACK_RESPONSE DRSUAPI DsGetNCChanges from workstation', protocol: 'TCP', srcPort: 50412, dstPort: 135, severity: 'CRITICAL', anomaly: 0.84 },
    ],
    response: {
      action: 'DISABLE_ACCOUNT',
      target: 'CORP\\hr.recruit07',
      rationale: 'Disable the account used for replication and force a credential reset.',
      alternatives: ['ISOLATE_HOST'],
    },
  },
  {
    id: 'INC-1038',
    threatName: 'Web Application Exploit Attempt',
    description: 'Log4Shell JNDI payloads injected into HTTP headers of the Student Portal from a known scanner.',
    sourceIp: '203.0.113.77',
    destinationIp: '10.0.20.5',
    assetId: 'AST-003',
    mitreTechniqueId: 'T1190',
    detectionSource: 'SURICATA',
    status: 'AWAITING_AUTHORIZATION',
    firstSeenMin: 180,
    lastSeenMin: 95,
    eventCount: 64,
    risk: { novelty: 0.35, confidence: 0.88, technique: 0.95, intel: 0.85 },
    explanation: [
      'Internet-facing application with an unpatched CVSS 10.0 vulnerability',
      'Payload matches Log4Shell exploitation (CVE-2021-44228)',
      'Source IP appears on an exploit-scanner blocklist',
    ],
    events: [
      { min: 180, source: 'SURICATA', eventType: 'JNDI Lookup in HTTP Header', signature: 'ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)', protocol: 'HTTP', srcPort: 41822, dstPort: 80, severity: 'CRITICAL', anomaly: 0.52 },
      { min: 150, source: 'THREAT_INTEL', eventType: 'Source on Exploit Scanner Blocklist', signature: 'Feed match: GreyNoise malicious scanner', protocol: 'HTTPS', srcPort: 41901, dstPort: 443, severity: 'HIGH', anomaly: 0.3 },
      { min: 95, source: 'SURICATA', eventType: 'Obfuscated Exploit Payload Variants', signature: 'ET EXPLOIT log4j JNDI obfuscated lookup', protocol: 'HTTP', srcPort: 42210, dstPort: 80, severity: 'HIGH', anomaly: 0.61 },
    ],
    response: {
      action: 'BLOCK_IP',
      target: '203.0.113.77',
      rationale: 'Block the scanner at the perimeter while the portal is patched.',
      alternatives: ['RATE_LIMIT'],
      authorization: { status: 'OTP_SENT', requestedMin: 9 },
    },
  },
  {
    id: 'INC-1036',
    threatName: 'Unusual Outbound Connection',
    description: 'Build server began a sustained TLS transfer to a never-before-seen external host with a rare JA3 fingerprint.',
    sourceIp: '10.0.40.12',
    destinationIp: '192.0.2.91',
    assetId: 'AST-008',
    mitreTechniqueId: 'T1071',
    detectionSource: 'ML_ANOMALY',
    status: 'NEW',
    firstSeenMin: 300,
    lastSeenMin: 40,
    eventCount: 112,
    risk: { novelty: 0.88, confidence: 0.74, technique: 0.7, intel: 0.35 },
    explanation: [
      'Destination never contacted by any NETRA asset in 90 days',
      '1.8 GB transferred — 40× this host’s normal egress',
      'Host runs Jenkins with a CVSS 9.8 file-read vulnerability',
    ],
    events: [
      { min: 300, source: 'ML_ANOMALY', eventType: 'Unusual Outbound Connection Volume', protocol: 'HTTPS', srcPort: 38122, dstPort: 443, severity: 'HIGH', anomaly: 0.81 },
      { min: 210, source: 'SURICATA', eventType: 'TLS Session with Rare JA3 Fingerprint', signature: 'ET JA3 Hash - Suspected Malware', protocol: 'HTTPS', srcPort: 38240, dstPort: 443, severity: 'MEDIUM', anomaly: 0.66 },
      { min: 40, source: 'ML_ANOMALY', eventType: 'Sustained Transfer to New Destination (1.8 GB)', protocol: 'HTTPS', srcPort: 38511, dstPort: 443, severity: 'HIGH', anomaly: 0.88 },
    ],
    response: {
      action: 'BLOCK_IP',
      target: '192.0.2.91',
      rationale: 'Block egress to the destination and review Jenkins job history.',
      alternatives: ['ISOLATE_HOST', 'MONITOR'],
    },
  },
  {
    id: 'INC-1035',
    threatName: 'Internal Port Scan',
    description: 'Lab workstation scanning finance subnet services with Nmap scripting engine.',
    sourceIp: '10.0.50.12',
    destinationIp: '10.0.10.15',
    assetId: 'AST-002',
    mitreTechniqueId: 'T1046',
    detectionSource: 'SURICATA',
    status: 'INVESTIGATING',
    firstSeenMin: 1560,
    lastSeenMin: 360,
    eventCount: 540,
    risk: { novelty: 0.4, confidence: 0.7, technique: 0.5, intel: 0.1 },
    explanation: [
      'Scan targets a high-criticality finance server',
      'Lab subnets have no business need to reach finance services',
    ],
    events: [
      { min: 1560, source: 'SURICATA', eventType: 'Horizontal Port Scan', signature: 'ET SCAN Nmap Scripting Engine User-Agent Detected', protocol: 'TCP', srcPort: 60122, dstPort: 443, severity: 'MEDIUM', anomaly: 0.44 },
      { min: 900, source: 'ML_ANOMALY', eventType: 'Scan Behaviour from Lab Workstation', protocol: 'TCP', srcPort: 60400, dstPort: 3389, severity: 'MEDIUM', anomaly: 0.57 },
      { min: 360, source: 'SURICATA', eventType: 'SMB Service Enumeration', signature: 'ET SCAN Behavioral Unusual Port 445 traffic', protocol: 'SMB', srcPort: 60911, dstPort: 445, severity: 'MEDIUM', anomaly: 0.39 },
    ],
    response: {
      action: 'MONITOR',
      target: '10.0.50.12',
      rationale: 'Monitor and confirm with Academic Labs whether this is a sanctioned exercise.',
      alternatives: ['BLOCK_IP'],
    },
  },
  {
    id: 'INC-1033',
    threatName: 'Phishing Link Click',
    description: 'Email from a known phishing domain delivered via the mail gateway; a recipient opened the credential-harvesting link.',
    sourceIp: '198.51.100.23',
    destinationIp: '10.0.0.25',
    assetId: 'AST-006',
    mitreTechniqueId: 'T1566',
    detectionSource: 'THREAT_INTEL',
    status: 'NEW',
    firstSeenMin: 2280,
    lastSeenMin: 2220,
    eventCount: 9,
    risk: { novelty: 0.3, confidence: 0.6, technique: 0.6, intel: 0.9 },
    explanation: [
      'Sender domain matched a phishing intelligence feed',
      'A recipient visited the credential-harvesting page',
    ],
    events: [
      { min: 2280, source: 'THREAT_INTEL', eventType: 'Inbound Email from Known Phishing Domain', signature: 'Feed match: OpenPhish', protocol: 'TCP', srcPort: 44120, dstPort: 25, severity: 'MEDIUM', anomaly: 0.2 },
      { min: 2220, source: 'SURICATA', eventType: 'Credential Harvesting Page Visited', signature: 'ET PHISHING Suspicious Microsoft 365 Login Page', protocol: 'HTTPS', srcPort: 52001, dstPort: 443, severity: 'MEDIUM', anomaly: 0.45 },
    ],
    response: {
      action: 'BLOCK_IP',
      target: '198.51.100.23',
      rationale: 'Block the sending infrastructure and reset the affected user’s password.',
      alternatives: ['MONITOR'],
    },
  },

  // ----------------------------------------------------------------- closed
  {
    id: 'INC-1031',
    threatName: 'DNS Tunneling Attempt',
    description: 'High-entropy DNS queries from the build server consistent with iodine tunneling.',
    sourceIp: '10.0.40.12',
    destinationIp: '198.18.0.53',
    assetId: 'AST-008',
    mitreTechniqueId: 'T1048',
    detectionSource: 'HYBRID',
    status: 'CONTAINED',
    firstSeenMin: 2880,
    lastSeenMin: 2790,
    closedMin: 2700,
    eventCount: 830,
    risk: { novelty: 0.85, confidence: 0.8, technique: 0.8, intel: 0.6 },
    explanation: ['High-entropy subdomains to a single resolver', 'Signature match for iodine DNS tunnel'],
    events: [
      { min: 2880, source: 'ML_ANOMALY', eventType: 'High-Entropy DNS Queries', protocol: 'DNS', srcPort: 53122, dstPort: 53, severity: 'HIGH', anomaly: 0.9 },
      { min: 2820, source: 'SURICATA', eventType: 'DNS Tunneling Pattern (iodine)', signature: 'ET TROJAN iodine DNS Tunnel Handshake', protocol: 'DNS', srcPort: 53190, dstPort: 53, severity: 'HIGH', anomaly: 0.7 },
    ],
    response: {
      action: 'BLOCK_IP',
      target: '198.18.0.53',
      rationale: 'Block the tunnel resolver and force internal DNS.',
      alternatives: ['ISOLATE_HOST'],
      authorization: { status: 'APPROVED', requestedMin: 2760, respondedMin: 2745 },
      containment: { status: 'VERIFIED', executedMin: 2740, verifiedMin: 2700, result: 'No DNS traffic to 198.18.0.53 for 30 min after block' },
      memory: {
        id: 'MEM-0212',
        outcome: 'CONTAINED',
        lessons: 'Build servers should resolve only through internal DNS; egress DNS now restricted by policy.',
        tags: ['dns', 'exfiltration', 'build-server'],
        similar: ['INC-1036'],
      },
    },
  },
  {
    id: 'INC-1028',
    threatName: 'RDP Brute Force',
    description: 'Off-hours RDP authentication failures against the finance server from a contractor VPN range.',
    sourceIp: '172.16.5.40',
    destinationIp: '10.0.10.15',
    assetId: 'AST-002',
    mitreTechniqueId: 'T1110',
    detectionSource: 'SURICATA',
    status: 'CONTAINED',
    firstSeenMin: 5760,
    lastSeenMin: 5610,
    closedMin: 5540,
    eventCount: 390,
    risk: { novelty: 0.45, confidence: 0.9, technique: 0.9, intel: 0.7 },
    explanation: ['Repeated RDP failures outside business hours', 'Known technique T1110'],
    events: [
      { min: 5760, source: 'SURICATA', eventType: 'RDP Authentication Failures', signature: 'ET SCAN Behavioral RDP Brute Force', protocol: 'RDP', srcPort: 61022, dstPort: 3389, severity: 'HIGH', anomaly: 0.5 },
      { min: 5650, source: 'ML_ANOMALY', eventType: 'Off-hours RDP Login Attempts', protocol: 'RDP', srcPort: 61210, dstPort: 3389, severity: 'HIGH', anomaly: 0.76 },
    ],
    response: {
      action: 'BLOCK_IP',
      target: '172.16.5.40',
      rationale: 'Block the source and require MFA on the contractor VPN.',
      alternatives: ['RATE_LIMIT'],
      authorization: { status: 'APPROVED', requestedMin: 5600, respondedMin: 5585 },
      containment: { status: 'VERIFIED', executedMin: 5580, verifiedMin: 5540, result: 'Zero authentication attempts from 172.16.5.40 after block' },
      memory: {
        id: 'MEM-0209',
        outcome: 'CONTAINED',
        lessons: 'Brute-force against remote-access services stopped within minutes of an IP block; recommend auto-escalation for repeat sources.',
        tags: ['brute-force', 'rdp', 'credential-access'],
        similar: ['INC-1042'],
      },
    },
  },
  {
    id: 'INC-1025',
    threatName: 'SMB Share Enumeration',
    description: 'Backup server enumerating SMB shares across the server VLAN.',
    sourceIp: '10.0.0.30',
    destinationIp: '10.0.0.10',
    assetId: 'AST-009',
    mitreTechniqueId: 'T1021',
    detectionSource: 'SURICATA',
    status: 'FALSE_POSITIVE',
    firstSeenMin: 8400,
    lastSeenMin: 8380,
    closedMin: 8200,
    eventCount: 22,
    risk: { novelty: 0.15, confidence: 0.3, technique: 0.4, intel: 0 },
    explanation: ['Enumeration pattern from a server host'],
    events: [
      { min: 8400, source: 'SURICATA', eventType: 'SMB Share Enumeration', signature: 'ET POLICY SMB2 Share Enumeration', protocol: 'SMB', srcPort: 44501, dstPort: 445, severity: 'LOW', anomaly: 0.12 },
    ],
    response: {
      action: 'MONITOR',
      target: '10.0.0.30',
      rationale: 'Confirm with infrastructure team.',
      alternatives: [],
      memory: {
        id: 'MEM-0205',
        outcome: 'FALSE_POSITIVE',
        lessons: 'Nightly backup job enumerates shares; backup-01 added to the SMB enumeration allow-list.',
        tags: ['false-positive', 'smb', 'backup'],
        similar: [],
      },
    },
  },
]

/** Uncorrelated background telemetry — realistic noise that never became an incident. */
export const BACKGROUND_EVENTS: (EventSeed & { srcIp: string; dstIp: string; status: 'NEW' | 'DISMISSED' })[] = [
  { min: 1.5, source: 'SURICATA', eventType: 'ICMP Echo Sweep', signature: 'ET SCAN ICMP PING Sweep', protocol: 'ICMP', severity: 'LOW', anomaly: 0.18, srcIp: '10.0.50.20', dstIp: '10.0.0.1', status: 'NEW' },
  { min: 7, source: 'THREAT_INTEL', eventType: 'Connection to Newly Registered Domain', signature: 'Feed match: NRD < 7 days', protocol: 'HTTPS', srcPort: 50991, dstPort: 443, severity: 'LOW', anomaly: 0.33, srcIp: '10.0.30.21', dstIp: '192.0.2.104', status: 'NEW' },
  { min: 26, source: 'ML_ANOMALY', eventType: 'Unusual VPN Login Time', protocol: 'TCP', dstPort: 88, severity: 'LOW', anomaly: 0.46, srcIp: '10.8.0.14', dstIp: '10.0.0.5', status: 'NEW' },
  { min: 47, source: 'SURICATA', eventType: 'Deprecated TLS 1.0 Negotiated', signature: 'ET POLICY TLS 1.0 Session', protocol: 'HTTPS', srcPort: 44012, dstPort: 443, severity: 'INFO', anomaly: 0.05, srcIp: '10.0.20.5', dstIp: '192.0.2.52', status: 'DISMISSED' },
  { min: 88, source: 'SURICATA', eventType: 'DNS Query to Dynamic DNS Provider', signature: 'ET INFO DYNAMIC_DNS Query to duckdns.org', protocol: 'DNS', srcPort: 53001, dstPort: 53, severity: 'LOW', anomaly: 0.29, srcIp: '10.0.30.33', dstIp: '10.0.0.53', status: 'NEW' },
  { min: 130, source: 'ML_ANOMALY', eventType: 'Traffic Peak Deviation — Student Portal', protocol: 'HTTPS', dstPort: 443, severity: 'INFO', anomaly: 0.22, srcIp: '100.64.12.9', dstIp: '10.0.20.5', status: 'DISMISSED' },
  { min: 156, source: 'SURICATA', eventType: 'SSH Login from New Country (VPN)', signature: 'NETRA Geo-velocity anomaly', protocol: 'SSH', srcPort: 50122, dstPort: 22, severity: 'LOW', anomaly: 0.38, srcIp: '10.8.0.22', dstIp: '10.0.40.12', status: 'DISMISSED' },
  { min: 204, source: 'THREAT_INTEL', eventType: 'Tor Exit Node Connection Attempt', signature: 'Feed match: Tor exit list', protocol: 'HTTPS', srcPort: 49330, dstPort: 443, severity: 'MEDIUM', anomaly: 0.41, srcIp: '192.0.2.201', dstIp: '10.0.20.5', status: 'NEW' },
  { min: 246, source: 'SURICATA', eventType: 'SQL Injection Probe', signature: 'ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT', protocol: 'HTTP', srcPort: 41020, dstPort: 80, severity: 'MEDIUM', anomaly: 0.35, srcIp: '203.0.113.140', dstIp: '10.0.20.5', status: 'NEW' },
  { min: 318, source: 'ML_ANOMALY', eventType: 'Unusual Database Query Volume', protocol: 'TCP', srcPort: 51900, dstPort: 5432, severity: 'LOW', anomaly: 0.49, srcIp: '10.0.10.15', dstIp: '10.0.0.10', status: 'DISMISSED' },
  { min: 402, source: 'SURICATA', eventType: 'Cleartext Password over FTP', signature: 'ET POLICY FTP Login Successful (non-anonymous)', protocol: 'FTP', srcPort: 50410, dstPort: 21, severity: 'LOW', anomaly: 0.12, srcIp: '10.0.50.31', dstIp: '10.0.0.30', status: 'NEW' },
  { min: 515, source: 'SURICATA', eventType: 'Outbound SMB to Internet', signature: 'ET POLICY Outbound SMB Traffic', protocol: 'SMB', srcPort: 49201, dstPort: 445, severity: 'MEDIUM', anomaly: 0.44, srcIp: '10.0.30.33', dstIp: '192.0.2.160', status: 'NEW' },
  { min: 690, source: 'ML_ANOMALY', eventType: 'After-hours Admin Login', protocol: 'RDP', srcPort: 51022, dstPort: 3389, severity: 'LOW', anomaly: 0.52, srcIp: '10.0.30.21', dstIp: '10.0.10.15', status: 'DISMISSED' },
  { min: 1020, source: 'THREAT_INTEL', eventType: 'Domain Matched Typosquat Watchlist', signature: 'Feed match: brand typosquat (netra-portal.example)', protocol: 'DNS', srcPort: 53441, dstPort: 53, severity: 'LOW', anomaly: 0.27, srcIp: '10.0.30.47', dstIp: '10.0.0.53', status: 'NEW' },
  { min: 1310, source: 'SURICATA', eventType: 'Self-signed Certificate Observed', signature: 'ET POLICY Self-Signed Cert', protocol: 'HTTPS', srcPort: 44821, dstPort: 443, severity: 'INFO', anomaly: 0.08, srcIp: '10.0.40.12', dstIp: '192.0.2.88', status: 'DISMISSED' },
]
