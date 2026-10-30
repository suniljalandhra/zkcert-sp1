export function EmlHelp() {
  return (
    <details className="help">
      <summary>How do I get the .eml file?</summary>
      <ul>
        <li>
          <b>Gmail (web):</b> open the completion email → ⋮ (More) → <i>Download message</i>.
        </li>
        <li>
          <b>Outlook (web):</b> open the email → ⋯ → <i>Save as</i> (or drag it to your desktop in the Outlook app).
        </li>
        <li>
          <b>Apple Mail:</b> select the email → File → <i>Save As…</i> → format <i>Raw Message Source</i>.
        </li>
      </ul>
      <p className="muted">
        Do not forward or edit the email first: forwarding re-signs it with your provider’s key and any edit breaks the DKIM signature. Search your inbox for
        “Your Certificate is Ready” (Coursera) or “Your completion certificate is ready” (Udemy).
      </p>
    </details>
  )
}
