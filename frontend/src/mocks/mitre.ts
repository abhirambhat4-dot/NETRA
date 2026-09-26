import type { MitreTechnique } from '@/api/types'

const url = (id: string) => `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`

export const MITRE_TECHNIQUES: MitreTechnique[] = [
  {
    id: 'T1110',
    name: 'Brute Force',
    tactic: 'Credential Access',
    description: 'Adversaries may use brute force techniques to gain access to accounts when passwords are unknown.',
    url: url('T1110'),
  },
  {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    description: 'Adversaries may abuse command and script interpreters such as PowerShell to execute commands.',
    url: url('T1059'),
  },
  {
    id: 'T1003',
    name: 'OS Credential Dumping',
    tactic: 'Credential Access',
    description: 'Adversaries may dump credentials from the operating system, e.g. LSASS memory or DCSync.',
    url: url('T1003'),
  },
  {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    description: 'Adversaries may exploit a weakness in an Internet-facing application to gain initial access.',
    url: url('T1190'),
  },
  {
    id: 'T1071',
    name: 'Application Layer Protocol',
    tactic: 'Command and Control',
    description: 'Adversaries may communicate using application layer protocols to blend in with normal traffic.',
    url: url('T1071'),
  },
  {
    id: 'T1046',
    name: 'Network Service Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may scan for services running on remote hosts to identify attack surface.',
    url: url('T1046'),
  },
  {
    id: 'T1566',
    name: 'Phishing',
    tactic: 'Initial Access',
    description: 'Adversaries may send phishing messages to gain access to victim systems.',
    url: url('T1566'),
  },
  {
    id: 'T1048',
    name: 'Exfiltration Over Alternative Protocol',
    tactic: 'Exfiltration',
    description: 'Adversaries may steal data over a protocol other than the C2 channel, such as DNS.',
    url: url('T1048'),
  },
  {
    id: 'T1021',
    name: 'Remote Services',
    tactic: 'Lateral Movement',
    description: 'Adversaries may use valid accounts to log into remote services such as SMB or RDP.',
    url: url('T1021'),
  },
]

export const mitreById = new Map(MITRE_TECHNIQUES.map((t) => [t.id, t]))
