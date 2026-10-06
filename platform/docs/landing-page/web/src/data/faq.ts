export interface FaqItem {
  q: string
  a: string
  category: string
}

export const FAQ: FaqItem[] = [
  {
    category: 'Today',
    q: 'What do I get?',
    a: 'A workspace that admits or refuses each action, an operator stop that does not wait for the model, and a receipt a reviewer can inspect. You run it with ./up.sh and open http://127.0.0.1:9091/.',
  },
  {
    category: 'Today',
    q: 'What is Connector?',
    a: 'An open-source control plane for agents that take real actions. It gives an agent an identity, explicit authority, one admission per action, runtime enforcement, operator stop, and an evidence trail. It is not an agent framework and it does not contain a language model.',
  },
  {
    category: 'Today',
    q: 'Do I rewrite my agent?',
    a: 'No. Bring the agent you already have, or assemble one in Connector. Point an OpenAI-compatible client at http://127.0.0.1:9091/v1. A pasted address is not a grant.',
  },
  {
    category: 'Today',
    q: 'Can an operator stop a running task?',
    a: 'Yes. Pause, stop, and Cease do not depend on the model agreeing. Cease fences the current generation and stops the next admission. It does not undo an effect that already happened.',
  },
  {
    category: 'Limits',
    q: 'Is this production-ready?',
    a: 'No. This site does not claim production readiness, security, correctness, safety, or compliance.',
  },
  {
    category: 'Limits',
    q: 'Are you SOC 2, HIPAA, or FedRAMP certified?',
    a: 'No. Receipts are something a reviewer can inspect. They are not a certificate.',
  },
  {
    category: 'Limits',
    q: 'Does Firecracker isolate every action?',
    a: 'No. Boot downloads the Firecracker binary and jailer. It does not create a microVM kernel or root filesystem. World dials today use dest-pinned Landlock.',
  },
  {
    category: 'Future',
    q: 'What is next?',
    a: 'Prove a real request through agentgateway, run a Firecracker microVM rather than only the binary, and show that an admitted effect actually passed through the backend that owns that job. A production claim waits until those are true.',
  },
  {
    category: 'Future',
    q: 'Why is agentgateway listed if traffic is not forwarded?',
    a: 'It is the traffic-plane target. The image can start. End-to-end forwarding has not been proven, so it stays denied. The Future section exists so that gap stays visible.',
  },
]

export const FAQ_CATEGORIES = [...new Set(FAQ.map(f => f.category))]
