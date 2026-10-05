/**
 * Google Apps Script — receive pilot form JSON, append to Sheet, email you.
 *
 * SETUP:
 * 1. New Google Sheet → copy its ID from the URL:
 *    https://docs.google.com/spreadsheets/d/{SHEET_ID}/edit
 * 2. Row 1 headers (optional but recommended):
 *    Timestamp | Name | Email | Company | Role | Use case | Source
 * 3. Extensions → Apps Script → paste this file as Code.gs
 * 4. Project Settings → Script properties → Add:
 *    - SHEET_ID = your spreadsheet id
 *    - NOTIFY_EMAIL = your@gmail.com
 *    - PILOT_SECRET = long random string (same value as Vercel APPS_SCRIPT_SECRET)
 * 5. Deploy → New deployment → Type: Web app
 *    - Execute as: Me
 *    - Who has access: Anyone  (secret in body protects abuse; optional: restrict to your workspace)
 * 6. Copy Web app URL → Vercel env APPS_SCRIPT_WEBAPP_URL
 */

function doPost(e) {
  const props = PropertiesService.getScriptProperties()
  var expected = props.getProperty('PILOT_SECRET')
  var sheetId = props.getProperty('SHEET_ID')
  var notify = props.getProperty('NOTIFY_EMAIL')

  if (!expected || !sheetId || !notify) {
    return jsonOut({ ok: false, error: 'Script properties not set' })
  }

  var body
  try {
    body = JSON.parse(e.postData.contents)
  } catch (err) {
    return jsonOut({ ok: false, error: 'Invalid JSON' })
  }

  if (body.secret !== expected) {
    return jsonOut({ ok: false, error: 'Unauthorized' })
  }

  var name = String(body.name || '').trim()
  var email = String(body.email || '').trim()
  var company = String(body.company || '').trim()
  var useCase = String(body.useCase || '').trim()
  var role = String(body.role || '').trim()
  var submittedAt = body.submittedAt || new Date().toISOString()
  var source = body.source || 'connector-landing'

  if (!name || !email || !company || !useCase) {
    return jsonOut({ ok: false, error: 'Missing fields' })
  }

  try {
    var sheet = SpreadsheetApp.openById(sheetId).getSheets()[0]
    sheet.appendRow([submittedAt, name, email, company, role, useCase, source])

    var subject = '[Connector] Pilot / access request: ' + company
    var mailBody =
      'New submission from the landing page.\n\n' +
      'Name: ' +
      name +
      '\n' +
      'Email: ' +
      email +
      '\n' +
      'Company: ' +
      company +
      '\n' +
      'Role: ' +
      (role || '—') +
      '\n\n' +
      'Use case:\n' +
      useCase +
      '\n\n' +
      '— Apps Script (Sheets + MailApp)'

    MailApp.sendEmail({
      to: notify,
      subject: subject,
      body: mailBody,
      replyTo: email,
    })
  } catch (err) {
    return jsonOut({ ok: false, error: String(err) })
  }

  return jsonOut({ ok: true })
}

function jsonOut(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(
    ContentService.MimeType.JSON
  )
}
