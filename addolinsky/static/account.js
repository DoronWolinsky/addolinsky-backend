// Website account page (D-133, D-139): Firebase sign-in, then link an existing install link or create an account,
// then the account dashboard. No backend session: every server call sends a fresh ID token in a same-origin JSON
// body. Text is set with textContent only. A new install link is shown once and never stored in the browser.
const cfg = JSON.parse(document.getElementById("cfg").textContent);
const A = await import(`${cfg.sdk}/firebase-app.js`);
const F = await import(`${cfg.sdk}/firebase-auth.js`);
const auth = F.getAuth(A.initializeApp(cfg.firebase));
await F.setPersistence(auth, F.browserSessionPersistence);   // this tab only; closing it signs out

const $ = (id) => document.getElementById(id);
const say = (text, ok = false) => { $("msg").textContent = text; $("msg").className = ok ? "msg ok" : "msg"; };
const VIEWS = ["signin", "verify", "onboard", "newlink", "dash", "dashBilling", "dashLink", "dashTranslations"];
const show = (...ids) => { for (const s of VIEWS) $(s).hidden = !ids.includes(s);
                           $("signout").hidden = ids.includes("signin"); };

const FIREBASE_ERRORS = {
  "auth/account-exists-with-different-credential":
    "כתובת הדוא\"ל הזו כבר רשומה בשיטת התחברות אחרת. התחברו בשיטה הקיימת; חשבונות לעולם אינם מאוחדים אוטומטית.",
  "auth/email-already-in-use": "כתובת הדוא\"ל הזו כבר רשומה. התחברו בשיטה שבה נרשמתם (סיסמה או Google).",
  "auth/invalid-credential": "פרטי ההתחברות שגויים.",
  "auth/wrong-password": "פרטי ההתחברות שגויים.",
  "auth/user-not-found": "פרטי ההתחברות שגויים.",
  "auth/weak-password": "הסיסמה קצרה מדי (לפחות 6 תווים).",
  "auth/invalid-email": "כתובת הדוא\"ל אינה תקינה.",
  "auth/too-many-requests": "יותר מדי ניסיונות. נסו שוב מאוחר יותר.",
  "auth/popup-closed-by-user": "חלון ההתחברות נסגר.",
  "auth/popup-blocked": "הדפדפן חסם את חלון ההתחברות. אפשרו חלונות קופצים לאתר ונסו שוב.",
  "auth/user-disabled": "ההתחברות הזו הושבתה.",
  "auth/network-request-failed": "שגיאת רשת. בדקו את החיבור ונסו שוב.",
};
const SERVER_ERRORS = {
  reauthentication_required: "לפעולה הזו נדרשת התחברות טרייה. התחברו שוב ונסו מיד.",
  email_not_verified: "יש לאמת את כתובת הדוא\"ל קודם.",
  user_unavailable: "קישור ההתקנה אינו תקף או שהחשבון מושבת.",
  invalid_install_link: "זה אינו קישור התקנה אישי של Addolinsky.",
  confirmation_required: "יש לסמן את תיבת האישור.",
  uid_linked_elsewhere: "ההתחברות הזו כבר מקושרת לחשבון אחר.",
  user_has_other_identity: "החשבון הזה כבר מקושר להתחברות אחרת. התחברו בשיטה שקישרתם בעבר.",
  too_many_attempts: "יותר מדי ניסיונות. נסו שוב בעוד דקה.",
  already_registered: "להתחברות הזו כבר יש חשבון.",
  registration_closed: "ההרשמה עדיין סגורה. נדרש קוד הזמנה.",
  invalid_invite: "קוד ההזמנה אינו תקף או שכבר נוצל.",
  terms_required: "יש לאשר את תנאי השימוש ומדיניות הפרטיות.",
  too_many_registrations: "נוצרו יותר מדי חשבונות מהרשת הזו היום. נסו שוב מחר.",
  registrations_paused: "ההרשמה מושהית זמנית. נסו שוב מחר.",
  owner_link_uses_cli: "את הקישור של בעל השירות מחליפים מהשרת בלבד.",
  billing_unavailable: "הפעולה אינה זמינה כרגע.",
  not_linked: "ההתחברות הזו אינה מקושרת לחשבון.",
};
const fbError = (e) => FIREBASE_ERRORS[e && e.code] || "ההתחברות נכשלה. נסו שוב.";
const PLAN_NAMES = { free: "חינמי", premium: "Premium", premium_canceling: "Premium (החידוש בוטל)",
                     expired: "חינמי (המנוי הסתיים)", refunded: "חינמי (הוחזר תשלום)",
                     disputed: "מושהה (בבירור מול חברת האשראי)", revoked: "מבוטל" };
const fmtDate = (ts) => ts ? new Date(ts * 1000).toLocaleDateString("he-IL") : "—";

async function post(path, body) {
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" },
                                body: JSON.stringify(body), credentials: "omit", cache: "no-store" });
  let data = {};
  try { data = await r.json(); } catch { /* empty */ }
  return { ok: r.ok, data };
}
async function idToken() { return auth.currentUser.getIdToken(); }

async function serverError(data, fallback) {
  say(SERVER_ERRORS[data.error] || fallback);
  if (data.error === "reauthentication_required") await F.signOut(auth);
}

async function refresh(user) {
  if (!user) { show("signin"); return; }
  if (!user.emailVerified) { $("verifyemail").textContent = user.email || ""; show("verify"); return; }
  const { ok, data } = await post("/account/status", { id_token: await idToken() });
  if (!ok) {
    if (data.error === "user_unavailable") say("החשבון המקושר מושבת.");
    else if (data.error === "pending_approval") say("החשבון ממתין לאישור.");
    else { say("לא ניתן לאמת את ההתחברות. התחברו שוב."); await F.signOut(auth); }
    return;
  }
  if (data.linked) { await loadDashboard(); return; }
  $("who").textContent = user.email || "";
  const reg = data.registration || {};
  $("regclosed").hidden = !!reg.open;
  $("inviteblock").hidden = !!reg.open;            // open registration: no invitation code needed
  $("termsrow").hidden = !reg.terms_required;
  show("onboard");
}

function list(el, items) {
  el.replaceChildren(...items.map((text) => { const li = document.createElement("li"); li.textContent = text; return li; }));
}

async function loadDashboard() {
  const { ok, data } = await post("/account/dashboard", { id_token: await idToken() });
  if (!ok) { await serverError(data, "טעינת החשבון נכשלה."); return; }
  const p = data.plan, c = data.credits;
  $("dEmail").textContent = data.account.email || "—";
  $("dProvider").textContent = data.account.sign_in_provider || "—";
  $("dPlan").textContent = data.account.role === "owner" ? "בעל השירות" : (PLAN_NAMES[p.state] || p.state);
  $("dPaid").textContent = p.premium ? fmtDate(p.paid_through) + (p.renews ? " (מתחדש אוטומטית)" : " (לא יתחדש)") : "—";
  if (!p.can_create) $("dCredits").textContent = "יצירת תרגומים חדשים זמינה למנויי Premium.";
  else if (c && c.limit != null) $("dCredits").textContent = `${c.remaining} מתוך ${c.limit} נותרו בתקופה הנוכחית (מתחדש ב-${fmtDate(c.period_end)})`;
  else $("dCredits").textContent = "לפי מכסות הבטא";
  list($("dGrants"), data.grants.map((g) => {
    const name = { beta: "הזמנה לבטא", test_premium: "גישת בדיקה (לא מנוי בתשלום)", manual: "הרשאה ידנית" }[g.kind] || g.kind;
    return `${name}${g.ends_at ? ` · עד ${fmtDate(g.ends_at)}` : ""}`;
  }));
  const b = data.billing;
  renderPlanOffers(b.checkout_available ? b.plans : []);
  $("cancelRenewal").hidden = !b.can_cancel;
  $("resumeRenewal").hidden = !b.can_resume;
  $("bText").textContent = b.provider_connected ? (p.premium ? "המנוי פעיל." : "אין מנוי פעיל.")
                                                : "רכישת מנוי Premium עדיין אינה זמינה. לא ייגבה ממך שום תשלום.";
  $("rotate").disabled = !data.install_link.rotatable;
  list($("dTranslations"), data.translations.length
    ? data.translations.map((t) => `${t.video_id} · ${fmtDate(t.created_at)} · ${t.available ? "זמין" : (t.status === "READY" ? "לא זמין" : "בתהליך / לא הושלם")}`)
    : ["עדיין לא יצרתם תרגומים."]);
  show("dash", "dashBilling", "dashLink", "dashTranslations");
}

function showNewLink(link) {
  $("newlinkvalue").value = link;
  show("newlink");
  $("newlinkvalue").focus(); $("newlinkvalue").select();
}

F.onAuthStateChanged(auth, (user) => refresh(user).catch(() => say("שגיאת רשת. נסו שוב.")));

$("google").onclick = async () => {
  say("");
  try { await F.signInWithPopup(auth, new F.GoogleAuthProvider()); } catch (e) { say(fbError(e)); }
};
$("pwform").onsubmit = async (ev) => {
  ev.preventDefault(); say("");
  try { await F.signInWithEmailAndPassword(auth, $("email").value.trim(), $("password").value); }
  catch (e) { say(fbError(e)); }
};
$("pwregister").onclick = async () => {
  say("");
  try {
    const cred = await F.createUserWithEmailAndPassword(auth, $("email").value.trim(), $("password").value);
    await F.sendEmailVerification(cred.user);
    say("נשלח קישור אימות לדוא\"ל.", true);
  } catch (e) { say(fbError(e)); }
};
$("pwreset").onclick = async () => {
  const email = $("email").value.trim();
  if (!email) { say("הזינו כתובת דוא\"ל."); return; }
  try { await F.sendPasswordResetEmail(auth, email); } catch { /* same answer either way: no account probing */ }
  say("אם הכתובת רשומה, נשלח אליה קישור לאיפוס סיסמה.", true);
};
$("resend").onclick = async () => {
  try { await F.sendEmailVerification(auth.currentUser); say("נשלח שוב.", true); } catch (e) { say(fbError(e)); }
};
$("verified").onclick = async () => {
  await auth.currentUser.reload();
  await auth.currentUser.getIdToken(true);             // the new token carries email_verified
  if (!auth.currentUser.emailVerified) { say("הכתובת עדיין לא אומתה."); return; }
  say(""); await refresh(auth.currentUser);
};
$("linkform").onsubmit = async (ev) => {
  ev.preventDefault(); say("");
  if (!auth.currentUser) { show("signin"); return; }
  const { ok, data } = await post("/account/link", { id_token: await idToken(),
    install_link: $("installlink").value, confirm: $("linkconfirm").checked === true });
  $("installlink").value = "";
  if (ok) { say("החשבון קושר. קישור ההתקנה שלכם ממשיך לעבוד כרגיל.", true); await loadDashboard(); return; }
  await serverError(data, "הקישור נכשל.");
};
$("registerform").onsubmit = async (ev) => {
  ev.preventDefault(); say("");
  const { ok, data } = await post("/account/register", { id_token: await idToken(),
    invite_code: $("invite").value.trim(), accept_terms: $("acceptterms").checked === true });
  if (ok) { say("החשבון נוצר.", true); showNewLink(data.install_link); return; }
  await serverError(data, "יצירת החשבון נכשלה.");
};
$("copylink").onclick = async () => {
  try { await navigator.clipboard.writeText($("newlinkvalue").value); say("הקישור הועתק.", true); }
  catch { $("newlinkvalue").select(); say("סמנו את הקישור והעתיקו ידנית."); }
};
$("installstremio").onclick = () => {
  const link = $("newlinkvalue").value;
  if (link) window.location.href = "stremio://" + link.split("://", 2)[1];
};
$("newlinkdone").onclick = async () => { $("newlinkvalue").value = ""; say(""); await loadDashboard(); };
$("rotate").onclick = async () => {
  if (!confirm("ליצור קישור התקנה חדש? הקישור הנוכחי יפסיק לעבוד מיד, ויהיה צריך להתקין את התוסף מחדש ב-Stremio.")) return;
  const { ok, data } = await post("/account/install-link/rotate", { id_token: await idToken(), confirm: true });
  if (ok) { showNewLink(data.install_link); return; }
  await serverError(data, "יצירת הקישור נכשלה.");
};
async function renewal(action, question) {
  if (!confirm(question)) return;
  const { ok, data } = await post(`/account/subscription/${action}`, { id_token: await idToken(), confirm: true });
  if (ok) { say("עודכן.", true); await loadDashboard(); return; }
  await serverError(data, "העדכון נכשל.");
}
$("cancelRenewal").onclick = () => renewal("cancel", "לבטל את החידוש האוטומטי? Premium יישאר פעיל עד סוף התקופה ששולמה.");
$("resumeRenewal").onclick = () => renewal("resume", "לחדש את המנוי האוטומטי?");
const formatPrice = (minor, currency) =>
  new Intl.NumberFormat("he-IL", { style: "currency", currency, maximumFractionDigits: minor % 100 ? 2 : 0 }).format(minor / 100);

function planOfferLabel(plan) {
  const price = formatPrice(plan.price_minor, plan.currency);
  if (plan.billing_interval === "year") {
    const perMonth = formatPrice(Math.round(plan.price_minor / 12), plan.currency);
    return `Premium שנתי · ${price} לשנה (${perMonth} לחודש) · ${plan.creations_per_month} תרגומים חדשים בחודש`;
  }
  return `Premium חודשי · ${price} לחודש · ${plan.creations_per_month} תרגומים חדשים בחודש`;
}

function renderPlanOffers(plans) {
  $("planOffers").replaceChildren(...plans.map((plan) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "primary";
    button.textContent = planOfferLabel(plan);
    button.onclick = () => startCheckout(plan.code);
    return button;
  }));
}

async function startCheckout(planCode) {
  const { ok, data } = await post("/account/checkout", { id_token: await idToken(), plan: planCode });
  if (ok && typeof data.redirect_url === "string" && data.redirect_url.startsWith("https://")) {
    window.location.href = data.redirect_url;            // the provider's hosted payment page
    return;
  }
  await serverError(data, "הרכישה אינה זמינה כרגע.");
}
if (new URLSearchParams(location.search).get("checkout") === "returned") {
  say("אם התשלום הושלם, המנוי יופעל רק אחרי אישור מחברת הסליקה. רעננו בעוד דקה.", true);
}
$("signout").onclick = async () => { await F.signOut(auth); say(""); };
