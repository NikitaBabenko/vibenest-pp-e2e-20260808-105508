const templateVersion = "preview-2026-08-06";
const projectName = "Project Payments QA";
const sellerName = "Pending project-owner legal review";
const supportContact = "Pending project-owner review";
const effectiveDate = "2026-08-08";

const sharedNotice = `
  <p><strong>Status:</strong> Preview/Draft. The project owner must review and publish a
  legally approved version before live payments are enabled.</p>
  <dl>
    <dt>Seller</dt><dd>${sellerName}</dd>
    <dt>Contact</dt><dd>${supportContact}</dd>
    <dt>Effective date</dt><dd>${effectiveDate}</dd>
  </dl>`;

export const legalPages = Object.freeze({
  "/terms": page("Terms of Sale", `${sharedNotice}
    <p>These draft terms govern the Pro monthly subscription and the simulator-only
    Lifetime one-time offer sold by this project owner. Each purchase is an independently
    tracked source of the <code>team_exports</code> entitlement. Pro supplies access while
    its signed authoritative period remains active or awaits a scheduled cancellation;
    Lifetime supplies one-time access unless that purchase is terminally refunded.</p>
    <p>Billing renews monthly until cancelled. A scheduled cancellation keeps access
    through its effective date. An immediate cancellation or approved refund changes
    access only after a verified terminal provider event is durably processed.</p>
    <p>The seller must add its final account eligibility, acceptable-use, availability,
    governing-law, and venue terms before enabling live checkout. VibeNest is not the
    seller. The <a href="/refund-policy">Refund Policy</a> and
    <a href="/privacy">Purchase Privacy Notice</a> form part of these terms.</p>`),

  "/privacy": page("Purchase Privacy Notice", `${sharedNotice}
    <p>This draft notice covers the minimum account identifier, checkout and portal
    session references, subscription and entitlement state, verified webhook event
    identifiers, timestamps, support records, and security evidence needed to operate
    the Pro subscription or Lifetime one-time purchase.</p>
    <p>The project uses those records to authorize team exports, prevent duplicate or
    out-of-order payment effects, support buyers, and investigate abuse. The final seller
    notice must state retention periods, processors, international transfers, buyer
    rights, and the approved privacy contact.</p>
    <p>Payment-card details must remain with the approved Merchant of Record/payment
    provider and must not enter this application's database or logs. The seller must link
    the approved provider's current privacy notice before live payments are enabled.</p>`),

  "/refund-policy": page("Refund Policy", `${sharedNotice}
    <p>The declared Project Payments refund window is 14 days from the relevant Pro or
    Lifetime purchase.
    The buyer must use the seller's final support channel and provide the transaction
    reference needed to locate the purchase, without sending card data.</p>
    <p>A scheduled Pro cancellation leaves <code>team_exports</code> available through the
    signed period end. An approved immediate refund revokes only the refunded purchase
    source after the signed terminal event is durably processed; another active Pro or
    Lifetime source continues to authorize access.</p>
    <p>The seller must add lawful product or jurisdiction exceptions and expected refund
    timing before live payments are enabled. Statutory consumer rights continue to apply.
    Once a Merchant of Record is approved, the buyer may also need to use its receipt or
    support flow. VibeNest does not pay or adjudicate this seller's refunds.</p>`)
});

export function sendLegalPage(response, route) {
  const html = legalPages[route];
  if (!html) return false;
  response.set("X-Robots-Tag", "noindex, nofollow");
  response.type("html").send(html);
  return true;
}

function page(title, content) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex,nofollow">
    <title>${title} — ${projectName}</title>
  </head>
  <body>
    <!-- VibeNest Project Payments seller template: ${templateVersion}. DRAFT / NOINDEX. -->
    <main>
      <p><a href="/">Project Payments QA</a></p>
      <h1>${title} — ${projectName}</h1>
      ${content}
    </main>
  </body>
</html>`;
}
