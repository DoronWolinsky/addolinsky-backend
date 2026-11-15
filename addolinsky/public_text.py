"""User-facing text: Stremio manifest description, Hebrew status subtitles and the copyright policy page.

Nothing here names providers, models, rules or pipeline stages (implementation details stay private).
The copyright policy is the wording the owner approved on 2026-11-07 (decision D1), reproduced verbatim.
"""

from __future__ import annotations

from html import escape

NAME = "Addolinsky"
DESCRIPTION = ("Automatic Hebrew subtitles for movies and series. Natural, context-aware translation with careful "
               "handling of Hebrew grammatical gender. Pick the Addolinsky track to request an episode; finished "
               "subtitles are shared with everyone who watches it. AI-generated, unofficial translations - mistakes "
               "can happen.")
# Stremio menu labels (both tracks are lang "heb"; the info track is listed first and never starts work)
INFO_LABEL = "Addolinsky · מידע ובקשת תרגום"
CONFIRM_LABEL = "Addolinsky · אישור: צור תרגום לעברית"

HEADER = "Addolinsky · תרגום לעברית (בטא)"
BETA = "בטא סגורה: מספר הבקשות מוגבל."
NOT_YET = "עדיין אין תרגום לעברית לפרק הזה."
HOW_TO_START = "לבקשת תרגום: בתפריט הכתוביות ← עברית, בחרו \"Addolinsky · אישור: צור תרגום לעברית\"."
QUOTA_LEFT = "נותרו לכם {day} בקשות היום ו-{month} בחודש הקרוב."
TV_HINT = "בטלוויזיה השמות לא מוצגים: האפשרות הראשונה של Addolinsky היא המידע, השנייה יוצרת את התרגום."
PAUSED = "בקשות תרגום חדשות עדיין סגורות. תרגומים שכבר קיימים זמינים."
QUEUED = "הבקשה התקבלה · ממתינה בתור (מקום {pos} מתוך {total})"
RUNNING = "מתרגם… {pct}%"
ETA = "זמן משוער לסיום: {eta}"
REFRESH = "לעדכון האחוזים והזמן: עברו לאפשרות Addolinsky השנייה, ואז חזרה. כשהתרגום מוכן הוא ייטען במקום ההודעה."
READY = "התרגום מוכן. לטעינה: עברו לאפשרות Addolinsky השנייה, ואז חזרה."
FAILED = "התרגום נכשל."
RETRY_HINT = ("התרגום נכשל. לניסיון חוזר: סגרו ופתחו את הסרטון, ובחרו שוב "
              "\"Addolinsky · אישור: צור תרגום לעברית\".")
FAILED_FINAL = "לא הצלחנו לתרגם את הפרק הזה, גם אחרי כמה ניסיונות."
NO_SOURCE = "לא נמצאו כתוביות באנגלית לפרק הזה, ולכן אי אפשר לתרגם אותו כרגע."
FUNDING = "המכסה החודשית ליצירת כתוביות חדשות נוצלה. כתוביות שכבר נוצרו עדיין זמינות."
DONATE = "אפשר לתמוך בפרויקט: {url}"
USER_LIMIT = "הגעתם למכסת הבקשות היומית. אפשר לנסות שוב מחר."
USER_MONTH_LIMIT = "הגעתם למכסת הבקשות החודשית שלכם בבטא."
DAILY_LIMIT = "השירות הגיע למכסת הבקשות היומית. אפשר לנסות שוב מחר."
AI_NOTE = "תרגום אוטומטי (AI), לא רשמי. ייתכנו טעויות."
# plans (services/entitlements.py)
PREMIUM_EXISTING = "לפרק הזה כבר יש תרגום לעברית, והוא זמין למנויי Premium."
PREMIUM_CREATE = "יצירת תרגומים חדשים זמינה למנויי Premium."
PREMIUM_NOT_SOLD = "מנוי Premium עדיין אינו זמין לרכישה."
CREDITS_LEFT = "נותרו לכם {left} מתוך {limit} תרגומים חדשים בתקופה הנוכחית (מתחדש ב-{reset})."
CREDITS_EXHAUSTED = "ניצלתם את {limit} התרגומים החדשים של התקופה הנוכחית. המכסה מתחדשת ב-{reset}."
RETRY_BY_REQUESTER = "ניסיון קודם לתרגם את הפרק נכשל. רק מי שביקש את התרגום יכול לנסות שוב."
JOINED_NO_ACCESS = "מישהו אחר כבר מתרגם את הפרק. התרגום יהיה זמין למנויי Premium."

RLE, PDF = "‫", "‬"


def _ts(ms: int) -> str:
    return f"{ms // 3600000:02d}:{ms // 60000 % 60:02d}:{ms // 1000 % 60:02d},{ms % 1000:03d}"


def status_srt(lines: list[str]) -> bytes:
    """The same RTL-wrapped message repeated in back-to-back cues (10 s for the first hour, then 2 min, up to 6 h):
    the Android TV player shows a cue only when it begins, so after re-selecting the track mid-video a single long
    cue stayed invisible (owner test 2026-11-09). Same convention as subtitles/rendering.py for the RTL marks."""
    body = "\n".join(f"{RLE}{ln}{PDF}" if any("֐" <= ch <= "׿" for ch in ln) else ln for ln in lines if ln)
    edges = list(range(0, 3_600_000, 10_000)) + list(range(3_600_000, 21_600_001, 120_000))
    return "".join(f"{i}\n{_ts(a)} --> {_ts(b)}\n{body}\n\n"
                   for i, (a, b) in enumerate(zip(edges, edges[1:], strict=False), 1)).encode()


POLICY = """### Copyright Policy — Addolinsky

Addolinsky respects intellectual property rights.

Our service generates Hebrew subtitles using subtitle sources that we believe are lawfully accessible and usable.

We do not host or distribute movies, television episodes, or audio recordings.

If you are a copyright holder or authorized representative and believe that subtitles made available through \
Addolinsky infringe your rights, please contact us with the title, relevant subtitle URL, and information supporting \
your claim.

We will promptly review credible complaints and remove or disable access to disputed subtitles where appropriate.

We are committed to cooperating with rights holders and addressing copyright concerns in good faith."""

AI_DISCLAIMER = ("Subtitles are generated automatically with AI. They are unofficial translations and may contain "
                 "errors. They are not affiliated with or endorsed by the rights holders of the titles.")


def policy_html(contact_email: str) -> str:
    paras = [p.strip() for p in POLICY.split("\n\n")]
    body = "".join(f"<h1>{escape(p[4:])}</h1>" if p.startswith("### ") else f"<p>{escape(p)}</p>" for p in paras)
    contact = (f'<p><b>Contact for copyright complaints and removal requests:</b> '
               f'<a href="mailto:{escape(contact_email)}">{escape(contact_email)}</a></p>' if contact_email else
               "<p><b>Contact for copyright complaints and removal requests:</b> not yet published.</p>")
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport "
            f"content='width=device-width,initial-scale=1'><title>Addolinsky — Copyright Policy</title>"
            f"<style>body{{font:16px/1.5 system-ui;max-width:720px;margin:24px auto;padding:0 16px}}</style></head>"
            f"<body>{body}{contact}<h2>About the subtitles</h2><p>{escape(AI_DISCLAIMER)}</p></body></html>")
