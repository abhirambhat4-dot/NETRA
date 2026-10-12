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
  lifecycle: 'lifecycle',
  capabilities: 'capabilities',
  scope: 'scope',
} as const

export type SectionId = (typeof SECTION_IDS)[keyof typeof SECTION_IDS]

export const NAV_ANCHORS: { label: string; id: SectionId }[] = [
  { label: 'How it works', id: SECTION_IDS.lifecycle },
  { label: 'Capabilities', id: SECTION_IDS.capabilities },
  { label: 'Scope', id: SECTION_IDS.scope },
]

export const HERO = {
  eyebrow: LANDING_TAGLINE,
  title: 'Know what to investigate first — and why.',
  description:
    'NETRA links the security evidence that is actually available, explains each risk priority with its reasons and missing evidence, and keeps a person in control of every response.',
  primaryCta: 'Sign in to NETRA',
  secondaryCta: 'See how it works',
  highlights: [
    'Reasons and evidence gaps shown for each priority',
    'Live tracking of submitted events and incident status',
    'Human approval before a response; containment is simulated',
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

export interface WorkflowStep {
  key: 'MONITOR' | 'DETECT' | 'ASSESS' | 'AUTHORIZE' | 'RESPOND' | 'LEARN'
  label: string
  summary: string
  detail: string
  simulated?: boolean
}

/** The landing page's condensed workflow. LIFECYCLE above stays the in-app seven-stage model. */
export const WORKFLOW: WorkflowStep[] = [
  {
    key: 'MONITOR',
    label: 'Monitor',
    summary: 'Track incoming events',
    detail: 'Collector submissions and dataset imports arrive as security events.',
  },
  {
    key: 'DETECT',
    label: 'Detect',
    summary: 'Correlate related activity',
    detail: 'Rule-based correlation links related events to incidents.',
  },
  {
    key: 'ASSESS',
    label: 'Assess',
    summary: 'Explain the risk',
    detail: 'Documented factors score each incident, with evidence and gaps shown.',
  },
  {
    key: 'AUTHORIZE',
    label: 'Authorize',
    summary: 'Verify and approve',
    detail: 'An analyst verifies; a person approves or rejects the recommended action.',
  },
  {
    key: 'RESPOND',
    label: 'Respond',
    summary: 'Record the response',
    detail: 'Containment is simulated: no host or firewall is changed.',
    simulated: true,
  },
  {
    key: 'LEARN',
    label: 'Learn',
    summary: 'Keep the lesson',
    detail: 'Outcomes and lessons are stored in Cyber Memory for review.',
  },
]

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

export type FeatureId = 'tracking' | 'ingestion' | 'correlation' | 'risk' | 'response' | 'assessment'

export interface Feature {
  id: FeatureId
  name: string
  description: string
  status: FeatureStatus
  boundary: string
}

export const FEATURES: Feature[] = [
  {
    id: 'tracking',
    name: 'Live Event Tracking',
    description:
      'The Live Event Collector lists events submitted to NETRA and refreshes automatically while open. Incidents are tracked by status through to closure.',
    status: 'available',
    boundary: 'Only events submitted to NETRA; no external feeds or agents are connected.',
  },
  {
    id: 'ingestion',
    name: 'Security Data Ingestion',
    description:
      'CSV uploads are validated against a supported profile. Accepted CIC-IDS2017 rows are stored as provenance-tagged security events.',
    status: 'in-progress',
    boundary: 'Dataset labels are not treated as proof of detection.',
  },
  {
    id: 'correlation',
    name: 'Detection & Evidence Correlation',
    description:
      'Rule-based correlation links events into incidents by shared IP address, time window and related event family.',
    status: 'in-progress',
    boundary: 'Automatic detection over imported datasets is not implemented yet.',
  },
  {
    id: 'risk',
    name: 'Explainable Risk Assessment',
    description:
      'Incidents are scored from six documented factors, each with its reason and supporting evidence. Missing evidence is listed, not hidden.',
    status: 'available',
    boundary: 'A heuristic based on the evidence available, not a guarantee.',
  },
  {
    id: 'response',
    name: 'Decision & Controlled Response',
    description:
      'An analyst verifies, a person approves or rejects the recommended action, and outcomes and lessons are kept in Cyber Memory.',
    status: 'available',
    boundary: 'Containment is simulated; no host or firewall is changed.',
  },
  {
    id: 'assessment',
    name: 'Security Assessment',
    description:
      'Assesses one asset at a time from its available records and keeps each result as a snapshot with traceable evidence.',
    status: 'in-progress',
    boundary: 'End-to-end browser and deployment verification is still pending.',
  },
]

/** The PDF's "Not claimed as completed or included by default" list, condensed. */
export const NON_CLAIMS: string[] = [
  'An AI or LLM analyst, or an autonomous learning system',
  'Active commercial SIEM or EDR integrations, or external live threat feeds',
  'Real host isolation or firewall changes',
  'Phishing, URL, QR or screenshot analysis',
  'Support for arbitrary datasets without a source-specific mapping',
  'Guaranteed detection of every attack',
]

export const CLOSING_CTA = {
  title: 'Review security evidence with the reasons in view.',
  description: 'Sign in to your NETRA workspace, or create an account to get started.',
} as const
