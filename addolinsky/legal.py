"""Versioned public legal documents: Terms of Service and Privacy Policy (D-134).

Each document version is immutable: its SHA-256 text hash is pinned in tests (`tests/test_legal.py`), so changing the
wording of a published version fails the suite and forces a new version.

STATUS: every version below is a draft in code. A version is in force only when the owner approves its rendered text
(operator name and contact filled from the settings) by adding that text's SHA-256, shown at the bottom of the page,
to ADDOLINSKY_LEGAL_APPROVED_SHA256 (D-141). Until then it is served with a "draft, not in force" banner and cannot
be accepted. Older versions keep their [square-bracket] placeholders and are never approved.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from html import escape

KINDS = ("terms", "privacy")


@dataclass(frozen=True)
class LegalDocument:
    kind: str           # terms | privacy
    version: str        # immutable once published
    status: str         # draft | approved (only approved versions can be accepted)
    title: str
    text: str           # plain text; paragraphs separated by blank lines; "## " starts a heading

    @property
    def text_hash(self) -> str:
        return hashlib.sha256(self.text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


TERMS_DRAFT_1 = """## 1. The service
Addolinsky ("the service") provides automatically generated Hebrew subtitles for movies and television episodes \
through the Stremio add-on system. The service is a beta. It may change, be limited or stop at any time.

## 2. Eligibility and accounts
Access currently requires a personal installation link issued by the operator. Your installation link is your \
credential: keep it private, because anyone holding it can use the service as you. You may optionally sign in on \
the website and link that sign-in to your existing account; signing in never replaces your installation link. \
[Minimum age: to be confirmed by the operator.]

## 3. AI-generated, unofficial subtitles
Subtitles are produced automatically with machine translation and AI. They are unofficial, may contain errors, and \
are not affiliated with or endorsed by the rights holders of the titles. Do not rely on them where accuracy matters.

## 4. Acceptable use
You agree not to: share your installation link with others; attempt to bypass request limits, quotas or access \
controls; use automated means to request translations in bulk; or use the service in breach of applicable law or \
the rights of others. We may limit, suspend or disable access that breaches these terms or endangers the service.

## 5. Intellectual property and sources
We do not host or distribute movies, episodes or audio. The service processes subtitle sources that we believe are \
lawfully accessible. Rights holders may report concerns under our Copyright Policy (/policy). You receive a personal, \
non-transferable permission to view the subtitles delivered to you through the service, for private viewing only.

## 6. Optional permission to share translations
This permission is separate from accepting these terms, is optional, and is off unless you turn it on. If you turn \
it on, you allow the operator to make Hebrew subtitles that are generated from translation requests you make AFTER \
the moment you turned it on available to other users of the service. Turning it on never changes subtitles created \
before that moment. You can turn it off at any time; turning it off applies to requests made after that moment. \
[Operator to confirm: how this permission interacts with the current beta, where finished subtitles for an episode \
are available to every beta user who watches it.]

## 7. Limits and fair use
Translation requests are limited per user and per period, and the service may pause new translations when its \
monthly capacity is used. Existing subtitles remain available where possible.

## 8. No warranty; limitation of liability
The service is provided "as is" and "as available", without warranties of any kind, to the extent permitted by law. \
[Liability limitation wording and governing law: to be provided by the operator after legal review.]

## 9. Changes
We may update these terms. A new version will be published here with a new version identifier, and continued use of \
features that require acceptance will require accepting the new version.

## 10. Contact
[Operator contact address.]"""

PRIVACY_DRAFT_1 = """## 1. Who we are
Addolinsky is operated by [operator name and contact address]. This policy explains what personal data the service \
processes and why.

## 2. Data we process
- Account: an internal user identifier, a one-way hash of your installation link (the link itself is not stored), \
your role, creation time and whether access is enabled.
- Requests: which titles and episodes you request or receive translations for, and when, to operate the queue, \
enforce request limits and attribute requests.
- Website sign-in (optional): if you link a sign-in, its identifier, e-mail address, whether the e-mail is verified, \
the sign-in method and the last sign-in time.
- Consent records: the versions of these documents you accepted, their text fingerprints, your optional sharing \
choice and the time of each choice.
- Network data: IP addresses are used transiently for rate limiting; for the sign-up limit a keyed one-way hash of \
the IP address is stored. Web server logs do not record request paths or headers.

## 3. Why we process it
To provide and secure the service, prevent abuse, enforce fair-use limits, honour your choices and respond to \
rights-holder requests. [Legal bases under applicable law: to be confirmed by the operator.]

## 4. Service providers
Website sign-in is provided by Google Firebase Authentication, which processes your sign-in data on our behalf. \
Subtitle text (not your account data) is processed by third-party machine-translation providers. The service runs \
on a rented server operated by a hosting provider. [Operator to confirm the provider list and locations.]

## 5. Sharing
We do not sell personal data. We do not share your personal data except with the service providers above, or where \
required by law.

## 6. Retention
Account, request and consent records are kept while your account exists and for [period] afterwards; consent \
records may be kept longer as proof of the choices made. [Retention periods: to be confirmed by the operator.]

## 7. Your rights
You may ask for access to, correction of or deletion of your personal data, and you may withdraw optional \
permissions at any time, by contacting [operator contact address].

## 8. Changes
A new version of this policy will be published here with a new version identifier."""

# Version 2026-11-15: open Free registration. {operator_name} and {contact_email} are filled from the settings
# (ADDOLINSKY_OPERATOR_NAME, ADDOLINSKY_CONTACT_EMAIL); the owner approves the rendered text by its SHA-256.
TERMS_2026_11_15 = """## 1. The service
Addolinsky ("the service") is operated by {operator_name}. It provides automatically generated Hebrew subtitles for \
movies and television episodes through the Stremio add-on system. The service is in beta: it may change, be limited \
or stop at any time.

## 2. Accounts
You create an account on this website by signing in with Google or with an e-mail address and password; an e-mail \
address must be verified before an account is created. You must be old enough to enter into these terms under the \
law that applies to you; if you are under 18, you need the permission of a parent or guardian. Keep your sign-in \
details and your personal Stremio installation link private: anyone holding the link can use the service as you. \
You can replace the link at any time on your account page.

## 3. Free accounts and paid plans
A Free account costs nothing and needs no payment method. It lets you view the translations available to Free \
accounts: the catalogue of translations that existed when Free accounts were introduced, and any translation you \
created yourself. A Free account cannot request new translations. Paid plans are not offered yet. If they are \
introduced, their price, credits and cancellation terms will be shown before any purchase and will require your \
separate agreement; nothing is ever charged without it.

## 4. AI-generated, unofficial subtitles
Subtitles are produced automatically with machine translation and AI. They are unofficial, may contain errors, and \
are not affiliated with or endorsed by the rights holders of the titles. Do not rely on them where accuracy matters.

## 5. Acceptable use
You agree not to: share your installation link or account with others; create accounts automatically or in bulk; \
attempt to bypass limits, quotas or access controls; or use the service in breach of applicable law or the rights \
of others. We may limit, suspend or close accounts that breach these terms or endanger the service.

## 6. Intellectual property and sources
We do not host or distribute movies, episodes or audio. The service processes subtitle sources that we believe are \
lawfully accessible. Rights holders may report concerns under our Copyright Policy (/policy), and translations may \
be removed. You receive a personal, non-transferable permission to view the subtitles delivered to you through the \
service, for private viewing only.

## 7. No warranty; limitation of liability
The free service is provided "as is" and "as available", without warranties of any kind. To the extent permitted \
by law, the operator is not liable for indirect, incidental or consequential damages arising from its use.

## 8. Ending your account
You may stop using the service at any time and ask us to delete your account through the contact address below. We \
may close accounts that breach these terms, or end the service, with reasonable notice where possible.

## 9. Law
These terms are governed by the laws of the State of Israel; the competent courts in Israel have jurisdiction.

## 10. Changes
We may update these terms. A new version will be published here with a new version identifier; continued use of \
features that require acceptance will require accepting the new version.

## 11. Contact
{operator_name}, {contact_email}"""

PRIVACY_2026_11_15 = """## 1. Who we are
Addolinsky is operated by {operator_name} ({contact_email}). This policy explains what personal data the service \
processes and why.

## 2. Data we process
- Account: an internal user identifier, a one-way hash of your installation link (the link itself is not stored), \
your plan, creation time and whether access is enabled.
- Sign-in: the identifier of your sign-in, your e-mail address, whether it is verified, the sign-in method (Google \
or e-mail and password) and the time of the last sign-in. Passwords are handled by Google Firebase Authentication \
and never reach our server.
- Use: which titles and episodes you request or receive subtitles for, and when, to operate the service, enforce \
limits and show you your own translations.
- Consent and account records: the versions of these documents you accepted, their text fingerprints and the time, \
and a log of security-relevant account actions (for example a replaced installation link).
- Network data: IP addresses are used transiently for rate limiting; to limit account creation, a keyed one-way \
hash of the IP address is stored with the account. Web server logs do not record request paths or headers.

## 3. Why we process it
To provide the service you signed up for, keep it secure, prevent abuse, honour your choices, respond to \
rights-holder requests and comply with the law.

## 4. Service providers
Sign-in is provided by Google Firebase Authentication, which processes your sign-in data on our behalf. Subtitle \
text (never your account data) is processed by third-party machine-translation providers. The service runs on a \
rented server in the European Union.

## 5. Sharing
We do not sell personal data and do not use it for advertising. We share it only with the service providers above, \
or where required by law.

## 6. Retention
Account, sign-in and use records are kept while your account exists. When you ask us to delete your account, we \
delete or anonymize them within 30 days, except consent and security records, which we keep only as long as needed \
as proof of the choices made and to protect the service, or as required by law.

## 7. Your rights
You may ask for access to, correction of or deletion of your personal data by writing to {contact_email}.

## 8. Changes
A new version of this policy will be published here with a new version identifier."""

DOCUMENTS: dict[tuple[str, str], LegalDocument] = {
    ("terms", "2026-11-draft-1"): LegalDocument("terms", "2026-11-draft-1", "draft", "Terms of Service",
                                                TERMS_DRAFT_1),
    ("privacy", "2026-11-draft-1"): LegalDocument("privacy", "2026-11-draft-1", "draft", "Privacy Policy",
                                                  PRIVACY_DRAFT_1),
    ("terms", "2026-11-15"): LegalDocument("terms", "2026-11-15", "draft", "Terms of Service", TERMS_2026_11_15),
    ("privacy", "2026-11-15"): LegalDocument("privacy", "2026-11-15", "draft", "Privacy Policy", PRIVACY_2026_11_15),
}
CURRENT = {"terms": "2026-11-15", "privacy": "2026-11-15"}
_UNSET_PARAMETER = "[not configured]"


def rendered_text(document: LegalDocument, settings) -> str:
    """The document text with the operator's name and contact address from the settings."""
    return (document.text.replace("{operator_name}", settings.operator_name.strip() or _UNSET_PARAMETER)
            .replace("{contact_email}", settings.contact_email.strip() or _UNSET_PARAMETER))


def rendered_hash(document: LegalDocument, settings) -> str:
    return hashlib.sha256(rendered_text(document, settings).encode("utf-8")).hexdigest()


def is_approved(document: LegalDocument, settings) -> bool:
    """Approved in code, or the owner approved exactly this rendered text by its SHA-256
    (ADDOLINSKY_LEGAL_APPROVED_SHA256). A text with an unset parameter is never approved."""
    if document.status == "approved":
        return True
    text = rendered_text(document, settings)
    return _UNSET_PARAMETER not in text and rendered_hash(document, settings) in settings.legal_approved_sha256


def get_document(kind: str, version: str | None = None) -> LegalDocument | None:
    if kind not in KINDS:
        return None
    return DOCUMENTS.get((kind, version or CURRENT[kind]))


def document_html(doc: LegalDocument, settings) -> str:
    """Same page shell and style as the Copyright Policy page (public_text.policy_html)."""
    approved = is_approved(doc, settings)
    parts = []
    for paragraph in rendered_text(doc, settings).split("\n\n"):
        if paragraph.startswith("## "):
            heading, _, paragraph = paragraph.partition("\n")
            parts.append(f"<h2>{escape(heading[3:])}</h2>")
        lines = [line for line in paragraph.split("\n") if line]
        if lines and all(line.startswith("- ") for line in lines):
            parts.append("<ul>" + "".join(f"<li>{escape(line[2:])}</li>" for line in lines) + "</ul>")
        elif lines:
            parts.append(f"<p>{escape(' '.join(lines))}</p>")
    banner = ("<p style='border:2px solid #c01c28;padding:8px 12px;border-radius:8px'><b>DRAFT, NOT IN FORCE.</b> "
              "This text has not been reviewed and cannot be accepted yet.</p>" if not approved else "")
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport "
            f"content='width=device-width,initial-scale=1'><title>Addolinsky — {escape(doc.title)}</title>"
            f"<style>body{{font:16px/1.5 system-ui;max-width:720px;margin:24px auto;padding:0 16px}}"
            f"code{{word-break:break-all}}</style></head>"
            f"<body><h1>{escape(doc.title)} — Addolinsky</h1>{banner}{''.join(parts)}"
            f"<p><small>Version {escape(doc.version)} · SHA-256 <code>{rendered_hash(doc, settings)}</code>"
            f"</small></p>"
            f"<p><a href=/terms>Terms of Service</a> · <a href=/privacy>Privacy Policy</a> · "
            f"<a href=/policy>Copyright Policy</a></p></body></html>")
