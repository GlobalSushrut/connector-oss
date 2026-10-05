/**
 * Google Apps Script — send yourself a Gmail when anyone submits the pilot form.
 *
 * SETUP (once):
 * 1. Open your Google Form (edit mode).
 * 2. Extensions → Apps Script (or ⋮ → Script editor).
 * 3. Paste this file contents into Code.gs (replace all).
 * 4. Set NOTIFY_EMAIL below to the Gmail address that should receive alerts.
 * 5. Save. Run → Authorize (allow Gmail send for the project).
 * 6. Triggers (⏰) → Add Trigger:
 *    - Function: onFormSubmit
 *    - Event: From form → On form submit
 *
 * Optional: remove MailApp and use GmailApp for richer HTML emails.
 */

var NOTIFY_EMAIL = 'your.address@gmail.com' // <-- change this

function onFormSubmit(e) {
  if (!NOTIFY_EMAIL || NOTIFY_EMAIL.indexOf('@') === -1) {
    throw new Error('Set NOTIFY_EMAIL in google-form-gmail-notify.gs')
  }
  var named = e.namedValues
  var lines = []
  for (var key in named) {
    if (!named.hasOwnProperty(key)) continue
    var vals = named[key]
    lines.push(key + ': ' + (vals && vals.length ? vals.join(', ') : ''))
  }
  var body =
    'New Connector pilot / interest form submission:\n\n' +
    lines.join('\n') +
    '\n\n— Sent by Apps Script (onFormSubmit)\n' +
    'Timestamp: ' + (e.response ? e.response.getTimestamp() : new Date())

  MailApp.sendEmail({
    to: NOTIFY_EMAIL,
    subject: '[Connector] New form response',
    body: body,
  })
}
