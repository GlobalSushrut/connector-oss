export const PILOT_TIERS = [
  {
    id: 'low-risk',
    badge: 'Low Risk Pilot',
    color: '#3ecf8e',
    title: 'One workflow. 30 days. Full governance.',
    forWho: 'Teams shipping AI that need to prove control before committing to a full deployment.',
    gets: [
      'ConnectorOS node deployed on your infrastructure',
      'One of the three ready workflows — DevGuard, TraceTramp, or WitnessCtl',
      'Policy contracts written and tuned by our team',
      'WitnessCtl audit receipts active from day one',
      'Direct Slack access to our engineering team',
      'End-of-pilot HMAC receipt bundle a reviewer can inspect — not a certification',
    ],
    outcome: 'After 30 days you have a working, governed, audited workflow — and a proof bundle regardless of what you decide next.',
    commitment: '30 days · One workflow · Fixed scope',
  },
  {
    id: 'beta',
    badge: 'Early Beta',
    color: '#5ba8ff',
    title: 'Controlled beta. Case-by-case agreement.',
    forWho: 'Teams with a specific compliance requirement or regulated environment that needs a purpose-designed program.',
    gets: [
      'Design-partner scope beyond the three ready workflows',
      'Policy written for your environment — not a sold certification',
      'Receipts a reviewer can inspect; framework mapping if we agree it is in scope',
      'Weekly architecture review with our team',
      'Priority bug fixes and feature requests',
      'Case-by-case SLA — agreed upfront',
    ],
    outcome: 'A production-grade ConnectorOS deployment designed for your environment — with ongoing engineering partnership.',
    commitment: 'Case-by-case · Custom scope · Formal agreement',
  },
  {
    id: 'cobuild',
    badge: 'Co-Build',
    color: '#a78bfa',
    title: 'We help you architect it into your product.',
    forWho: 'Platform teams and AI infrastructure builders who want ConnectorOS governance embedded into what they ship to customers.',
    gets: [
      'Joint architecture design sessions',
      'ConnectorOS integrated into your deployment pipeline',
      'Custom plugin compositions for your product use cases',
      'White-label and OEM options discussed case by case',
      'Shared roadmap input — you shape what we build next',
      'Long-term engineering partnership',
    ],
    outcome: 'ConnectorOS becomes a native capability of your product — governance built in, not bolted on.',
    commitment: 'Long-term · Partnership agreement · Selected teams only',
  },
]

export const WHY_PAY = [
  { q: 'Why pay for a pilot?', a: 'Because free pilots produce free attention. Paid pilots produce real deployment. When you pay, you get our full engineering time, direct Slack access, and a team with skin in the game. We are not doing demos — we are deploying governance into your production environment.' },
  { q: 'What does paying actually get me?', a: 'Direct access to the engineers who built it. Policy contracts written for your environment. A working audited workflow after 30 days. An HMAC receipt bundle a reviewer can inspect — not a SOC 2 certificate. And certainty about whether ConnectorOS is the right infrastructure for you — with no further obligation.' },
  { q: 'What if it does not work for us?', a: 'You walk away with a proof bundle showing what governance on your infrastructure looks like. That evidence has value regardless. No long contracts. No lock-ins. The pilot is designed to prove control — not to trap you.' },
  { q: 'Why are you so selective?', a: 'We are a small team. We go deep on every deployment. Taking a pilot means our engineers are in your environment writing your policy contracts. We choose teams where we know we can deliver something real.' },
]

export const IS_FIT = [
  'You are shipping AI into production — not planning to someday',
  'You need evidence of what an agent did — not a dashboard screenshot',
  'You need to prove what your AI did — not just observe that it ran',
  'You have a CISO, compliance officer, or auditor who needs evidence, not promises',
  'You can commit to one workflow, one team, 30 days — not a kitchen-sink evaluation',
  'You prefer self-hosted infrastructure you control over a platform you depend on',
]

export const NOT_FIT = [
  'You only want the 90-minute playground — that is free; a pilot is a real node on your infrastructure',
  'You are still in the "exploring AI" phase with no production deployment',
  'You need a pre-built SaaS dashboard with zero integration work',
  'You want governance as a checkbox — not as actual enforcement',
]

export const PROCESS = [
  { num: '01', title: 'Fill the form', detail: 'Tell us your industry, compliance requirement, which plugin or workflow you want to start with, and your timeline. We read every submission personally.' },
  { num: '02', title: 'We review and respond', detail: 'Within 48 hours we assess fit. If we think we can deliver something real for you, we reach out directly.' },
  { num: '03', title: 'One scoping call', detail: 'We confirm the workflow scope, compliance requirements, success metric, and pilot tier. One focused call — no sales deck.' },
  { num: '04', title: 'Agreement and deployment', detail: 'Simple agreement. You deploy the ConnectorOS binary on your infrastructure. We configure policy contracts and connect to your environment.' },
  { num: '05', title: '30 days of governed execution', detail: 'Your workflow runs under full ConnectorOS governance. We tune policy, review audit receipts weekly, and fix anything that does not work. Direct Slack throughout.' },
  { num: '06', title: 'Proof bundle and your decision', detail: 'On day 30 you receive an HMAC receipt bundle you can inspect. Expand, continue as beta, or walk away. No pressure. The bundle is yours regardless. It is evidence, not a certification.' },
]
