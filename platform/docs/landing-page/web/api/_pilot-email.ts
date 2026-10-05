type SubmissionEmailInput = {
  name: string
  email: string
  company: string
  companySize?: string
  role?: string
  products?: string
  primaryUseCase?: string
  timeline?: string
  useCase: string
}

function fromEmail(): string {
  return process.env.CONNECTOR_EMAIL_FROM || 'connectorprotoos@gmail.com'
}

function fromName(): string {
  return process.env.CONNECTOR_EMAIL_FROM_NAME || 'Connector'
}

function notifyEmail(): string {
  return process.env.PILOT_NOTIFICATION_EMAIL || 'connectorprotoos@gmail.com'
}

async function sendResendEmail(input: {
  to: string
  replyTo?: string
  subject: string
  text: string
}): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY
  if (!apiKey) {
    throw new Error('Resend is not configured')
  }

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: `${fromName()} <${fromEmail()}>`,
      to: [input.to],
      reply_to: input.replyTo,
      subject: input.subject,
      text: input.text,
    }),
  })

  if (!response.ok) {
    const message = await response.text()
    throw new Error(`Resend error: ${response.status} ${message}`)
  }
}

export async function sendPilotSubmissionEmails(input: SubmissionEmailInput): Promise<void> {
  await sendResendEmail({
    to: notifyEmail(),
    replyTo: input.email,
    subject: `New pilot request from ${input.name} (${input.company})`,
    text: [
      'New pilot request received.',
      '',
      `Name:            ${input.name}`,
      `Email:           ${input.email}`,
      `Company:         ${input.company}`,
      `Company size:    ${input.companySize || 'Not provided'}`,
      `Role:            ${input.role || 'Not provided'}`,
      `Products:        ${input.products || 'Not specified'}`,
      `Primary use case:${input.primaryUseCase || 'Not provided'}`,
      `Timeline:        ${input.timeline || 'Not provided'}`,
      '',
      'What are they building?',
      input.useCase,
    ].join('\n'),
  })

  await sendResendEmail({
    to: input.email,
    subject: 'We received your ConnectorOS pilot request',
    text: [
      `Hi ${input.name},`,
      '',
      'Thanks for applying to the ConnectorOS controlled pilot.',
      'We read every submission personally and will respond within 48 hours if you are a fit for the current cohort.',
      '',
      'Here is what you submitted:',
      `Company:          ${input.company}`,
      `Role:             ${input.role || 'Not provided'}`,
      `Products:         ${input.products || 'Not specified'}`,
      `Primary use case: ${input.primaryUseCase || 'Not provided'}`,
      `Timeline:         ${input.timeline || 'Not provided'}`,
      '',
      input.useCase,
      '',
      'ConnectorOS Team',
    ].join('\n'),
  })
}
