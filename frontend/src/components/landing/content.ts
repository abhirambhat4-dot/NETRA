/**
 * Public landing page copy — the single source of truth for what NETRA claims before sign-in.
 *
 * Scope and limitations come from NETRA_Project_Overview_Final.pdf. Feature statuses were checked
 * against the backend services and tests; change a status only when the code proves it.
 * This module has no imports so `node --test` can load it directly (tests/landingContent.test.ts).
 */

export const LANDING_TAGLINE = 'Evidence-grounded cybersecurity decision intelligence'

/** Must match ROUTES.login / ROUTES.register in src/lib/navigation.ts (asserted by tests). */
export const LANDING_LINKS = {
  signIn: '/login',
  register: '/register',
} as const

export const SECTION_IDS = {
  main: 'main-content',
  problem: 'problem',
  lifecycle: 'lifecycle',
  capabilities: 'capabilities',
  prioritisation: 'prioritisation',
  scope: 'scope',
} as const

export type SectionId = (typeof SECTION_IDS)[keyof typeof SECTION_IDS]

export const NAV_ANCHORS: { label: string; id: SectionId }[] = [
  { label: 'Lifecycle', id: SECTION_IDS.lifecycle },
  { label: 'Capabilities', id: SECTION_IDS.capabilities },
  { label: 'Scope', id: SECTION_IDS.scope },
]

export const HERO = {
  eyebrow: LANDING_TAGLINE,
  title: 'Know what to investigate first — and why.',
  description:
    'NETRA connects the security evidence that is actually available, explains each risk priority with the factors behind it and the evidence that is missing, and helps analysts review decisions and sensible next steps before anything is acted on.',
  primaryCta: 'Sign in to NETRA',
  secondaryCta: 'See how it works',
  highlights: [
    'Reasons and evidence gaps shown for each priority',
    'Human approval before a response action',
    'Containment simulated in the current scope',
  ],
} as const

export interface EvidenceStep {
  key: 'evidence' | 'reason' | 'risk' | 'next-step' | 'traceability'
  label: string
  text: string
}

/** Mirrors the PDF's "Illustrative output (not an actual finding)". Never real data. */
export const EVIDENCE_PREVIEW = {
  label: 'Illustrative — not a real finding',
  title: 'Example finding: suspicious network activity',
  steps: [
    { key: 'evidence', label: 'Evidence', text: 'Source records and fields that support the rule match.' },
    { key: 'reason', label: 'Reason', text: 'The implemented logic matched a documented condition.' },
    { key: 'risk', label: 'Risk', text: 'Calculated from the documented method and the context available.' },
    { key: 'next-step', label: 'Next step', text: 'Investigate or monitor, as appropriate.' },
    { key: 'traceability', label: 'Traceability', text: 'Source records, rule and version behind the result.' },
  ] satisfies EvidenceStep[],
} as const

export const PROBLEMS: { title: string; text: string }[] = [
  {
    title: 'Security evidence is scattered',
    text: 'Events, alerts, asset details, vulnerabilities and threat indicators often live in separate places, so it is hard to see which records are actually related.',
  },
  {
    title: 'Priorities need understandable reasons',
    text: 'A score on its own is hard to trust. Analysts need to see which factors raised a priority and which information was missing.',
  },
  {
    title: 'Decisions need a traceable trail',
    text: 'When a response is approved, the evidence, the approval and the outcome should stay connected so they can be reviewed later.',
  },
]

export type LifecycleKey = 'DETECT' | 'UNDERSTAND' | 'PRIORITISE' | 'VERIFY' | 'AUTHORIZE' | 'CONTAIN' | 'LEARN'

export interface LifecycleStage {
  key: LifecycleKey
  label: string
  /** The PDF's one-line description of the stage. */
  summary: string
  detail: string
}

export const LIFECYCLE: LifecycleStage[] = [
  {
    key: 'DETECT',
    label: 'Detect',
    summary: 'Find candidate activity',
    detail: 'Security events are reviewed to surface activity that may be worth investigating.',
  },
  {
    key: 'UNDERSTAND',
    label: 'Understand',
    summary: 'Add supported context',
    detail: 'Events, assets and indicators are linked only where matching evidence supports it.',
  },
  {
    key: 'PRIORITISE',
    label: 'Prioritise',
    summary: 'Rank by evidence and risk',
    detail: 'A documented risk method ranks findings and shows the factors behind each rank.',
  },
  {
    key: 'VERIFY',
    label: 'Verify',
    summary: 'Check findings',
    detail: 'An analyst checks the finding before any response is considered.',
  },
  {
    key: 'AUTHORIZE',
    label: 'Authorize',
    summary: 'Record approval',
    detail: 'A person approves or rejects the recommended action, and the decision is recorded.',
  },
  {
    key: 'CONTAIN',
    label: 'Contain',
    summary: 'Simulate or execute an approved action',
    detail: 'In the current scope containment is simulated: no host or firewall is changed.',
  },
  {
    key: 'LEARN',
    label: 'Learn',
    summary: 'Record outcome and lesson',
    detail: 'The outcome and lessons are stored in Cyber Memory for later review.',
  },
]

export const LIFECYCLE_NOTE =
  'Containment is simulated in the current scope. Real host or firewall changes would require a separately implemented, secure and approved integration.'

export type FeatureStatus = 'available' | 'in-progress' | 'planned'

export const STATUS_META: Record<FeatureStatus, { label: string; description: string }> = {
  available: {
    label: 'Available',
    description: 'Implemented and covered by backend tests, within the stated boundary.',
  },
  'in-progress': {
    label: 'In progress',
    description: 'Partly implemented; the boundary says what is not done yet.',
  },
  planned: {
    label: 'Readiness / planned',
    description: 'Designed for, but not an active capability.',
  },
}

export type FeatureId =
  | 'ingestion'
  | 'correlation'
  | 'risk'
  | 'response'
  | 'memory'
  | 'assessment'
  | 'live-feed'

export interface Feature {
  id: FeatureId
  name: string
  description: string
  status: FeatureStatus
  boundary: string
}

export const FEATURES: Feature[] = [
  {
    id: 'ingestion',
    name: 'Security Data Ingestion',
    description:
      'Signed-in users can upload a CSV file and validate it against a supported profile: a generic CSV profile or CIC-IDS2017. Each upload is recorded as an import batch with accepted and rejected row counts and reasons, and a file that was already validated is detected.',
    status: 'in-progress',
    boundary:
      'Uploads are validated and recorded only. Rows are not yet stored as security events or used to create findings.',
  },
  {
    id: 'correlation',
    name: 'Detection & Evidence Correlation',
    description:
      'Events arrive through manual intake or the authenticated web collector. Rule-based correlation links events to an incident when they share an IP address, fall within a time window and belong to a related event family.',
    status: 'in-progress',
    boundary:
      'Automatic detection over imported datasets is not implemented yet. Dataset labels are not treated as proof of independent detection.',
  },
  {
    id: 'risk',
    name: 'Explainable Risk Assessment',
    description:
      'Incidents are scored from six documented factors. Each factor carries its reason and supporting evidence, and missing evidence is listed rather than silently ignored.',
    status: 'available',
    boundary:
      'A score is only as reliable as the documented method and the evidence available. It is a heuristic, not a guarantee.',
  },
  {
    id: 'response',
    name: 'Decision & Controlled Response',
    description:
      'NETRA recommends a response action with its rationale. An analyst verifies the incident, a person approves or rejects the action, and the response outcome is recorded.',
    status: 'available',
    boundary:
      'Containment is simulated in the current scope. Real infrastructure changes would need separate secure integrations and approval controls.',
  },
  {
    id: 'memory',
    name: 'Cyber Memory & Learning',
    description:
      'When an incident is closed, its response outcome and lessons learned can be recorded in Cyber Memory, where they can be searched and reviewed later.',
    status: 'available',
    boundary:
      'Records support human review. NETRA does not claim to learn on its own or to adjust future scores from these records.',
  },
  {
    id: 'assessment',
    name: 'Security Assessment',
    description:
      'Assesses one asset at a time from the available asset, vulnerability, incident, event and threat-indicator records, and keeps each result as a snapshot with traceable evidence.',
    status: 'in-progress',
    boundary:
      'The assessment engine and API exist and have backend tests, but end-to-end verification in the browser and in deployment is still pending.',
  },
  {
    id: 'live-feed',
    name: 'Future Live-Feed Readiness',
    description:
      'Submitted events go through a shared intake service. The authenticated web collector uses it today, and authorised live feeds are intended to use the same path later.',
    status: 'planned',
    boundary:
      'Readiness is not an active integration. No live feed adapters are connected, and collector events are stored as manually submitted data.',
  },
]

export interface RiskFactor {
  /** Key in FACTOR_WEIGHTS, backend/app/services/risk_engine.py (asserted by tests). */
  key: 'asset_criticality' | 'vulnerability' | 'anomaly' | 'detection' | 'threat_intelligence' | 'attack_context'
  label: string
  text: string
}

export const RISK_FACTORS: RiskFactor[] = [
  { key: 'asset_criticality', label: 'Asset criticality', text: 'How important the affected asset is.' },
  { key: 'vulnerability', label: 'Vulnerability', text: 'Known vulnerability severity on the affected asset.' },
  { key: 'anomaly', label: 'Anomaly', text: 'Behavioural anomaly evidence on the linked events.' },
  { key: 'detection', label: 'Detection', text: 'How much the detection source can be relied on, from signature alerts to unverified manual input.' },
  { key: 'threat_intelligence', label: 'Threat intelligence', text: 'Active matches against known threat indicators.' },
  { key: 'attack_context', label: 'Attack context', text: 'Patterns in the linked events, such as reconnaissance, authentication or outbound activity.' },
]

export const PRIORITISATION = {
  eyebrow: 'Explainable prioritisation',
  title: 'Every priority shows its working.',
  description:
    'A risk priority is built from documented factors. For each factor NETRA shows the reason and the supporting evidence, so an analyst can see why an incident ranks where it does.',
  missingTitle: 'Missing evidence is flagged, not hidden',
  missingText:
    'When a factor has no supporting evidence, it contributes nothing and the gap is listed. The absence of a threat-intelligence match, for example, is not treated as proof that activity is benign.',
} as const

export const PRINCIPLES: { title: string; text: string }[] = [
  {
    title: 'Traceable evidence',
    text: 'Decisions should be supported by evidence that can be traced back to its source records.',
  },
  {
    title: 'Human authorisation',
    text: 'A person must approve a recommended response action before it is carried out.',
  },
  {
    title: 'Simulated containment',
    text: 'Containment is simulated in the current scope. No host, network or firewall is changed.',
  },
  {
    title: 'Recorded lessons',
    text: 'Outcomes and lessons can be recorded and reviewed. Automatic learning is not claimed.',
  },
  {
    title: 'Honest examples',
    text: 'Illustrative examples are always labelled and are never presented as live findings.',
  },
  {
    title: 'Readiness is not integration',
    text: 'Future live-feed readiness is not presented as a currently active integration.',
  },
]

/** The PDF's "Not claimed as completed or included by default" list. */
export const NON_CLAIMS: string[] = [
  'An AI or LLM analyst, or an autonomous learning system.',
  'Website or URL safety checks, phishing or email analysis, QR analysis or screenshot verification.',
  'Active commercial SIEM or EDR integrations.',
  'Real host isolation or firewall changes.',
  'Support for arbitrary datasets without a source-specific mapping.',
  'Guaranteed detection of every attack, or a fixed processing time regardless of dataset size and hardware.',
]

export const CLOSING_CTA = {
  title: 'Review security evidence with the reasons in view.',
  description: 'Sign in to your NETRA workspace, or create an account to get started.',
} as const
