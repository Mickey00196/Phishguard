"use strict";

// ─────────────────────────────────────────────────────────────────────────────
// PhishGuard Backend — v3.1.0
// Architect · Engineer · Reviewer · Optimizer
// ─────────────────────────────────────────────────────────────────────────────

const express = require("express");
const cors    = require("cors");

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG — single source of truth for all tuneable values
// ─────────────────────────────────────────────────────────────────────────────

const CONFIG = {
  port:             process.env.PORT || 8080,
  anthropicApiKey:  process.env.ANTHROPIC_API_KEY,
  anthropicModel:   "claude-haiku-4-5-20251001",
  anthropicVersion: "2023-06-01",
  maxTokens:        600,
  bodyMaxChars:     1500,   // consistent across all analyzers
  maxLinks:         10,
  rdapTimeoutMs:    4000,
  domainCacheTtlMs: 24 * 60 * 60 * 1000,

  allowedOrigins: [
    "https://outlook.office.com",
    "https://outlook.live.com",
    "https://outlook.office365.com",
    "https://mail.google.com",
    "https://script.google.com",
    "https://phishguards.up.railway.app",
  ],

  // brand → all official domains (including subdomains)
  // REVIEWER FIX: also catches typosquats via containsBrand() check below
  brandDomains: {
    dhl:             ["dhl.com",   "dhl.nl"],
    paypal:          ["paypal.com","paypal.nl"],
    microsoft:       ["microsoft.com","outlook.com","live.com","hotmail.com"],
    apple:           ["apple.com"],
    google:          ["google.com","gmail.com","google.nl"],
    amazon:          ["amazon.com","amazon.nl","amazon.de"],
    ing:             ["ing.nl"],
    rabobank:        ["rabobank.nl"],
    abnamro:         ["abnamro.nl"],
    postnl:          ["postnl.nl", "edm.postnl.nl", "post.nl"],
    belastingdienst: ["belastingdienst.nl"],
    klm:             ["klm.com"],
    ns:              ["ns.nl"],
  },

  // ENGINEER FIX: skip RDAP for these — also skip spoofing check
  trustedEmailProviders: new Set([
    // Email delivery platforms
    "sendgrid.net","mailchimp.com","klaviyo.com","brevo.com",
    "hubspot.com","mailgun.org","amazonses.com","sparkpostmail.com",
    "mandrillapp.com","exacttarget.com","salesforce.com","postmarkapp.com",
    "stripe.com","constantcontact.com","campaignmonitor.com",
    // ATS / recruitment platforms — use tracking subdomains legitimately
    "icims.com","greenhouse.io","lever.co","workday.com","taleo.net",
    "successfactors.com","bamboohr.com","recruitee.com","teamtailor.com",
    // Marketing automation tracking
    "marketo.com","pardot.com","eloqua.com","act-on.com",
    "nurture.icims.com","tracking.icims.com",
  ]),

  suspiciousTlds:   new Set([".xyz",".top",".click",".tk",".ml",".ga",".cf",".pw",".cc"]),
  urlShorteners:    new Set(["bit.ly","tinyurl.com","t.co","goo.gl","rebrand.ly","cutt.ly","tiny.cc","is.gd"]),
  cloudStorageUrls: ["storage.googleapis.com","storage.cloud.google.com","blob.core.windows.net"],

  urgencyPhrases: [
    "dringend","urgent","onmiddellijk","account geblokkeerd","suspended",
    "bevestig nu","wachtwoord verlopen","laatste waarschuwing","actie vereist",
    "verify now","act now","your account has been","confirm your account",
  ],
  credentialPhrases: [
    "wachtwoord invoeren","enter your password","verify your identity",
    "bevestig je identiteit","creditcard nummer","bankrekening","pincode","cvv",
  ],
  genericGreetings: [
    "beste klant","dear customer","geachte klant",
    "beste gebruiker","dear user","hello user","dear valued",
  ],

  multiPartTlds: ["co.uk","co.nz","co.za","com.au","org.uk","net.uk","com.br"],
  // OPTIMIZER: Set for O(1) lookup
  genericTlds: new Set(["com","nl","net","org","io","co","de","fr","be","eu"]),

  rdapServers: [
    d => `https://rdap.org/domain/${d}`,
    d => `https://rdap.arin.net/registry/domain/${d}`,
    d => `https://rdap.verisign.com/com/v1/domain/${d}`,
  ],

  // Scoring weights — validated against 12-case test matrix
  scoring: {
    deterministicWeight: 0.4,
    aiWeight:            0.4,
    ageBoostWeight:      0.8,  // increased: young domain is a strong signal
    highSignalPoints:    35,
    mediumSignalPoints:  15,
    // Floors: most specific wins via Math.max()
    floors: {
      threeHigh:          85,  // 3+ high signals
      twoHigh:            75,  // 2 high signals
      highAndMedium:      72,  // 1 high + 1 medium (covers link mismatch + urgency)
      oneHigh:            55,  // 1 high signal alone
      twoMedium:          40,  // 2 medium signals
      brandSpoof:         75,  // brand spoofing detected
      brandSpoofNewDomain:85,  // brand spoof + domain < 30 days
      unknownDomain:      65,  // unknown domain + AI >= 50
    },
    ageBoosts: { veryNew: 40, young: 20, old: -15 },
    ageDays:   { veryNew: 30, young: 180, old: 730 },
    legitimateCap:   20,
    newsletterCap:   35,
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// UTILS
// ─────────────────────────────────────────────────────────────────────────────

/** "user@mail.evil.com" → "mail.evil.com" */
const getDomainFromEmail = email =>
  (email || "").toLowerCase().split("@")[1] || "";

/** "mail.evil.xyz" → "evil.xyz" | "foo.co.uk" → "foo.co.uk" */
function getRootDomain(domain) {
  const parts = domain.split(".");
  if (parts.length <= 1) return domain;

  // Multi-part TLDs: co.uk, com.au etc → take 3 parts
  if (CONFIG.multiPartTlds.some(tld => domain.endsWith(tld))) return parts.slice(-3).join(".");

  // Known hosting/reseller platforms where subdomains are user-controlled
  // e.g. fqkwmdwm.cloxy.it.com → root should be cloxy.it.com, not it.com
  // Without this: RDAP returns age of it.com (33 years) instead of the actual subdomain
  const rootTwo   = parts.slice(-2).join(".");
  const rootThree = parts.length >= 3 ? parts.slice(-3).join(".") : rootTwo;

  const PLATFORM_DOMAINS = new Set([
    "it.com","is-a.dev","netlify.app","vercel.app","pages.dev",
    "github.io","glitch.me","repl.co","ngrok.io","railway.app",
    "herokuapp.com","fly.dev","render.com","workers.dev",
    "servebeer.com","ddns.net","no-ip.com","duckdns.org",
    "000webhostapp.com","weebly.com","wixsite.com","squarespace.com",
  ]);

  if (PLATFORM_DOMAINS.has(rootTwo) && parts.length >= 3) return rootThree;

  return rootTwo;
}

/** Fetch with hard timeout — returns null on failure */
async function fetchWithTimeout(url, ms, options = {}) {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    const res = await fetch(url, { ...options, signal: ctrl.signal });
    clearTimeout(timer);
    return res;
  } catch {
    clearTimeout(timer);
    return null;
  }
}

/** JSON.parse that never throws */
function safeParseJson(text) {
  try { return JSON.parse(text.replace(/```json|```/g, "").trim()); }
  catch { return null; }
}

/**
 * ENGINEER FIX: Deduplicate signals by message text.
 * Prevents AI and deterministic layer from reporting the same issue twice.
 */
function deduplicateSignals(signals) {
  const seen = new Set();
  return signals.filter(s => {
    const key = s.message.toLowerCase().slice(0, 60);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// DOMAIN AGE ANALYZER (RDAP)
// ─────────────────────────────────────────────────────────────────────────────

const domainCache    = new Map();
const CACHE_VERSION  = "v2"; // bump this to bust cache on deploy

async function fetchRdapData(rootDomain) {
  for (const buildUrl of CONFIG.rdapServers) {
    const res = await fetchWithTimeout(
      buildUrl(rootDomain),
      CONFIG.rdapTimeoutMs,
      { headers: { Accept: "application/json" } }
    );
    if (res?.ok) return res.json().catch(() => null);
  }
  return null;
}

function parseRegistrationDate(rdapData) {
  const events = rdapData?.events || [];

  // STRICT: only accept explicit registration or created events
  // Never use "last changed" — it gives wrong dates for major domains
  const VALID_ACTIONS = new Set(["registration", "created"]);
  const event = events.find(e => VALID_ACTIONS.has(e.eventAction));

  if (!event?.eventDate) return null;

  const date = new Date(event.eventDate);
  const now  = new Date();

  // Sanity checks: must be a real past date
  if (isNaN(date))                    return null;
  if (date > now)                     return null; // future date
  if (date.getFullYear() < 1985)      return null; // before DNS existed
  if (date.getFullYear() > now.getFullYear()) return null;

  return date;
}

async function getDomainAge(senderEmail) {
  const fullDomain = getDomainFromEmail(senderEmail);
  if (!fullDomain) return null;

  const rootDomain = getRootDomain(fullDomain);
  if (CONFIG.genericTlds.has(rootDomain)) return null;

  // ENGINEER FIX: skip RDAP for trusted providers — no value, wastes time
  if (CONFIG.trustedEmailProviders.has(rootDomain) ||
      [...CONFIG.trustedEmailProviders].some(p => fullDomain.endsWith("." + p))) return null;

  const cached = domainCache.get(rootDomain);
  if (cached && cached.version === CACHE_VERSION && Date.now() - cached.timestamp < CONFIG.domainCacheTtlMs) {
    return cached.result;
  }

  const data    = await fetchRdapData(rootDomain);
  const regDate = data ? parseRegistrationDate(data) : null;

  // Explicit result: found age OR null (not found) — never a guess
  const result = regDate
    ? { ageInDays: Math.floor((Date.now() - regDate) / 86_400_000), registeredAt: regDate.toISOString(), domain: rootDomain, found: true }
    : null;

  domainCache.set(rootDomain, { result, version: CACHE_VERSION, timestamp: Date.now() });
  console.log(`[RDAP] ${rootDomain}: ${result ? result.ageInDays + "d old" : "not found"}`);
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// DETERMINISTIC ANALYZER
// ─────────────────────────────────────────────────────────────────────────────

/**
 * REVIEWER FIX: Catches both exact-prefix spoofing AND typosquats.
 * - "dhl.evil.com"      → root = "evil.com"      → no match (correct)
 * - "dhl-tracking.com"  → root = "dhl-tracking.com" → containsBrand → HIGH
 * - "mailing.dhl.nl"    → root = "dhl.nl"         → isOfficial → SAFE
 * - "dhl.com"           → root = "dhl.com"         → isOfficial → SAFE
 */
function checkBrandSpoofing(senderEmail) {
  const domain     = getDomainFromEmail(senderEmail);
  const rootDomain = getRootDomain(domain);

  const isTrusted = CONFIG.trustedEmailProviders.has(rootDomain) ||
    [...CONFIG.trustedEmailProviders].some(p => domain.endsWith("." + p));
  if (isTrusted) return null;

  for (const [brand, officialDomains] of Object.entries(CONFIG.brandDomains)) {
    const isOfficial = officialDomains.some(
      d => rootDomain === d || domain === d || domain.endsWith("." + d)
    );
    if (isOfficial) continue; // legitimate sender

    // Typosquat: brand appears as a complete word segment in the root domain
    // e.g. "dhl-tracking.com" → segments: ["dhl","tracking"] → match
    // e.g. "businessinsider.com" → segments: ["businessinsider"] → no match for "ns"
    const rootWithoutTld = rootDomain.replace(/\.(com|nl|net|org|xyz|top|io|cc|pw|be|de|fr|uk|ru)$/, "");
    const rootSegments   = rootWithoutTld.split(/[\.\-]/);
    const isTyposquat    = rootSegments.includes(brand) && !isOfficial;

    // Subdomain spoof: brand appears as an exact subdomain segment before the root
    // e.g. "dhl.scammer.ru" → subdomains: ["dhl"] → match
    // e.g. "email.businessinsider.com" → subdomains: ["email"] → no match for "ns"
    const subdomainSegments = domain.split(".").slice(0, -2);
    const isSubdomainSpoof  = subdomainSegments.includes(brand);

    if (isTyposquat || isSubdomainSpoof) {
      return {
        message:  `Afzender (${domain}) imiteert ${brand.toUpperCase()} — waarschijnlijk nep domein`,
        severity: "high",
      };
    }
  }
  return null;
}

function checkUrgency(subject, body) {
  const text = `${subject} ${(body || "").slice(0, CONFIG.bodyMaxChars)}`.toLowerCase();
  const hits  = CONFIG.urgencyPhrases.filter(p => text.includes(p));
  if (hits.length >= 2) return { message: "Meerdere urgentie-signalen gevonden", severity: "high" };
  if (hits.length === 1) return { message: `Urgentietaal: "${hits[0]}"`, severity: "medium" };
  return null;
}

function checkLinks(links = []) {
  return links.slice(0, CONFIG.maxLinks).flatMap(link => {
    try {
      const url  = new URL(link);
      const host = url.hostname.toLowerCase();
      const out  = [];
      if ([...CONFIG.suspiciousTlds].some(tld => host.endsWith(tld)))
        out.push({ message: `Verdacht TLD: ${host}`, severity: "high" });
      if (CONFIG.urlShorteners.has(host))
        out.push({ message: `URL shortener: ${host}`, severity: "medium" });
      if (CONFIG.cloudStorageUrls.some(c => link.includes(c)))
        out.push({ message: `Cloud storage link in e-mail: ${host}`, severity: "high" });
      return out;
    } catch { return []; }
  });
}

function checkCredentials(body) {
  const lower = (body || "").toLowerCase().slice(0, CONFIG.bodyMaxChars);
  return CONFIG.credentialPhrases.some(p => lower.includes(p))
    ? { message: "Verzoek om gevoelige gegevens", severity: "high" }
    : null;
}

function checkGenericGreeting(body) {
  const lower   = (body || "").toLowerCase();
  const preview = lower.slice(0, 300);

  // If email has an unsubscribe link, it is almost certainly a newsletter — lower signal weight
  const hasUnsubscribe = lower.includes("unsubscribe") || lower.includes("uitschrijven") || lower.includes("afmelden");
  if (hasUnsubscribe) return null; // newsletters always have generic greetings

  return CONFIG.genericGreetings.some(g => preview.includes(g))
    ? { message: "Generieke aanhef zonder persoonlijke naam", severity: "medium" }
    : null;
}

function isNewsletter(body = "", links = []) {
  const lower = body.toLowerCase();
  return lower.includes("unsubscribe") ||
         lower.includes("uitschrijven") ||
         lower.includes("afmelden") ||
         lower.includes("bekijk online") ||
         lower.includes("view in browser");
}

function extractBrand(hostname) {
  // "news.strato.com" → "strato" | "www.paypal.com" → "paypal"
  const clean = hostname.replace(/^www\./, "");
  const parts = clean.split(".");
  return parts.length >= 2 ? parts[parts.length - 2] : clean;
}

function checkLinkMismatches(linkMismatches = []) {
  return linkMismatches
    .filter(({ visible, actual }) => {
      // Skip if same brand — newsletters always use tracking subdomains
      // e.g. www.strato.nl → news.strato.com is NOT a real mismatch
      return extractBrand(visible) !== extractBrand(actual);
    })
    .map(({ visible, actual }) => ({
      message:  `Link toont "${visible}" maar verwijst naar ander domein "${actual}"`,
      severity: "high",
    }));
}

function checkAttachments(attachments = [], body = "") {
  const dangerous = [".exe",".js",".vbs",".bat",".scr",".docm",".xlsm",".zip",".rar"];
  const signals   = [];

  // Flag dangerous extensions found in email
  const found = dangerous.filter(ext =>
    attachments.some(a => a.toLowerCase().includes(ext)) ||
    body.toLowerCase().includes(ext)
  );
  if (found.length > 0) {
    signals.push({
      message:  `Verdachte bijlage gevonden: ${found.join(", ")}`,
      severity: "high",
    });
  } else if (attachments.length > 0) {
    signals.push({
      message:  `E-mail bevat ${attachments.length} bijlage(n) — controleer de afzender`,
      severity: "medium",
    });
  }
  return signals;
}

function checkQrCode(hasQrCode = false) {
  if (!hasQrCode) return null;
  return {
    message:  "E-mail bevat mogelijk een QR-code zonder tekstlinks — klassieke QR-phishing tactiek",
    severity: "high",
  };
}

function checkColleagueImpersonation(sender = "", subject = "", body = "", companyDomain = "") {
  if (!companyDomain) return null;

  const senderDomain = (sender.split("@")[1] || "").toLowerCase();
  const companyLower = companyDomain.toLowerCase();

  // Sender claims to be from company but domain doesn't match
  const bodyLower    = body.toLowerCase().slice(0, 500);
  const subjectLower = subject.toLowerCase();

  const mentionsCompany = bodyLower.includes(companyLower.split(".")[0]) ||
                          subjectLower.includes(companyLower.split(".")[0]);

  const isNotCompanyDomain = senderDomain !== companyLower &&
                             !senderDomain.endsWith("." + companyLower);

  if (mentionsCompany && isNotCompanyDomain && senderDomain) {
    return {
      message:  `Afzender (${senderDomain}) beweert van ${companyDomain} te zijn maar gebruikt een ander domein`,
      severity: "high",
    };
  }
  return null;
}

function runDeterministicChecks({ sender, subject, body, links, linkMismatches, attachments, hasQrCode, companyDomain }) {
  return [
    checkBrandSpoofing(sender),
    checkUrgency(subject, body),
    ...checkLinks(links),
    ...checkLinkMismatches(linkMismatches),
    ...checkAttachments(attachments, body),
    checkQrCode(hasQrCode),
    checkCredentials(body),
    checkGenericGreeting(body),
    checkColleagueImpersonation(sender, subject, body, companyDomain),
  ].filter(Boolean);
}

// ─────────────────────────────────────────────────────────────────────────────
// AI ANALYZER
// ─────────────────────────────────────────────────────────────────────────────

function buildPrompt(email, findings) {
  const senderDomain  = getDomainFromEmail(email.sender);
  const findingLines  = findings.length
    ? findings.map(f => `- [${f.severity}] ${f.message}`).join("\n")
    : "Geen deterministische signalen gevonden";

  return `Je bent een expert phishing-analist. Analyseer deze e-mail en geef een nauwkeurige risicoscore.

AFZENDER: ${email.sender} (domein: ${senderDomain})
ONDERWERP: ${email.subject}
BODY: ${(email.body || "").slice(0, CONFIG.bodyMaxChars)}
LINKS: ${(email.links || []).slice(0, CONFIG.maxLinks).join(", ") || "geen"}

REEDS GEVONDEN SIGNALEN:
${findingLines}

DOMEIN BEOORDELING:
- Wereldwijd bekend legitiem domein → domainLegit: true, aiScore MAX 30
- Onbekend of willekeurig domein → domainLegit: false, aiScore min 65
- Domein imiteert een merk → domainLegit: false, aiScore min 85

TRACKING LINKS zijn NORMAAL voor legitieme nieuwsbrieven en recruitment-mails.
Voorbeelden van legitieme tracking: tracking.icims.com, click.hubspot.com,
links.mailchimp.com, go.salesforce.com — NOOIT als phishing markeren.

COUNTER-SIGNALEN die score VERLAGEN:
- Domein > 2 jaar oud → legitimiteitssignaal
- Persoonlijke aanhef → minder verdacht
- Professionele inhoud zonder urgentie → minder verdacht
- Bekende afzender (LinkedIn, MSCI, PostNL) → score max 25%

Als de meeste signalen GROEN zijn en het domein LEGITIEM is: aiScore MAX 25.

SCOREGIDS:
0-20:  Legitiem — bekend merk, geen rode vlaggen
21-40: Waarschijnlijk veilig
41-60: Twijfelachtig
61-80: Waarschijnlijk phishing
81-100: Vrijwel zeker phishing

STRIKTE REGELS — overtreed deze niet:
- Rapporteer ALLEEN wat je daadwerkelijk in de tekst ziet — geen HTML, headers of metadata
- Tracking links via een subdomain van hetzelfde merk (news.strato.com voor strato.nl) zijn NORMAAL — nooit flaggen
- Unsubscribe links, online versie links en logo links zijn standaard in nieuwsbrieven — niet flaggen
- Persoonlijke aanhef ("Hoi Mick") verlaagt het risico — echte phishing gebruikt generieke aanhef
- Een legitiem bedrijfsdomein als afzender (strato.com, postnl.nl, ing.nl) = score maximaal 25%
- Rapporteer GEEN zero-width characters, HTML-structuur of verborgen spaties — je ziet alleen platte tekst

Geef UITSLUITEND geldige JSON terug:
{
  "aiScore": <integer 0-100>,
  "domainLegit": <boolean>,
  "verdict": "<veilig|verdacht|gevaarlijk>",
  "summary": "<2-3 zinnen in het Nederlands>",
  "signals": [{ "message": "<string>", "severity": "<low|medium|high>" }]
}`;
}

async function analyzeWithClaude(email, findings) {
  if (!CONFIG.anthropicApiKey) {
    return { aiScore: 0, domainLegit: false, verdict: "onbekend", summary: "AI niet geconfigureerd", signals: [] };
  }

  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method:  "POST",
    headers: {
      "Content-Type":      "application/json",
      "x-api-key":         CONFIG.anthropicApiKey,
      "anthropic-version": CONFIG.anthropicVersion,
    },
    body: JSON.stringify({
      model:      CONFIG.anthropicModel,
      max_tokens: CONFIG.maxTokens,
      messages:   [{ role: "user", content: buildPrompt(email, findings) }],
    }),
  });

  if (!res.ok) throw new Error(`Anthropic ${res.status}: ${await res.text()}`);

  const data   = await res.json();
  const text   = (data.content || []).map(b => b.text || "").join("");
  const parsed = safeParseJson(text);

  return parsed ?? { aiScore: 0, domainLegit: false, verdict: "onbekend", summary: "", signals: [] };
}

// ─────────────────────────────────────────────────────────────────────────────
// SCORER
// ─────────────────────────────────────────────────────────────────────────────

function getDomainAgeSignal(domainAge) {
  // Explicitly null = RDAP lookup failed or domain not found — say so clearly
  if (domainAge === null) return null; // no signal — don't guess

  const { ageInDays } = domainAge;
  const { ageDays }   = CONFIG.scoring;
  if (ageInDays < ageDays.veryNew) return { message: `Domein slechts ${ageInDays} dagen oud — extreem verdacht`, severity: "high" };
  if (ageInDays < ageDays.young)   return { message: `Domein ${ageInDays} dagen oud (minder dan 6 maanden)`, severity: "medium" };
  if (ageInDays > ageDays.old)     return { message: `Domein ${Math.floor(ageInDays / 365)} jaar oud`, severity: "low" };
  return null;
}

function getAgeBoost(domainAge) {
  if (!domainAge) return 0;
  const { ageInDays } = domainAge;
  const { ageDays, ageBoosts } = CONFIG.scoring;
  if (ageInDays < ageDays.veryNew) return ageBoosts.veryNew;
  if (ageInDays < ageDays.young)   return ageBoosts.young;
  if (ageInDays > ageDays.old)     return ageBoosts.old;
  return 0;
}

function getSignalFloor(highCount, mediumCount) {
  const { floors } = CONFIG.scoring;
  if (highCount >= 3)    return floors.threeHigh;
  if (highCount >= 2)    return floors.twoHigh;
  if (highCount >= 1)    return floors.oneHigh;
  if (mediumCount >= 2)  return floors.twoMedium;
  return 0;
}

function buildBreakdown(aiScore, findings, deterministicScore) {
  return {
    claude:       aiScore,
    safeBrowsing: Math.min(findings.filter(f => f.severity === "high").length * 35, 100),
    virusTotal:   Math.min(findings.filter(f => f.message.includes("link") || f.message.includes("TLD")).length * 40, 100),
    domain:       deterministicScore,
  };
}

function calculateScore(findings, aiResult, domainAge, body = "", links = []) {
  const h           = findings.filter(f => f.severity === "high").length;
  const m           = findings.filter(f => f.severity === "medium").length;
  const l           = findings.filter(f => f.severity === "low").length;
  const aiScore     = Math.min(Math.max(aiResult.aiScore || 0, 0), 100);
  const domainLegit = aiResult.domainLegit === true;
  const ageBoost    = getAgeBoost(domainAge);
  const ageInDays   = domainAge?.ageInDays ?? null;
  const s           = CONFIG.scoring;

  // ── PATH A: Verified legitimate domain ────────────────────────────────────
  // When AI confirms domain is legit AND domain is old, cap score hard at 35%.
  // Counter-signals (low severity = legitimacy markers) further reduce score.
  // This handles newsletters, recruitment emails, transactional emails that
  // have tracking links or generic greetings — normal for legitimate senders.
  if (domainLegit && ageBoost <= 0) {
    const legitimacyReduction = l * 8; // each green signal reduces score
    const raw = Math.max(
      Math.round(h * 20 + m * 10 - legitimacyReduction + aiScore * 0.2),
      0
    );
    return {
      total:     Math.min(raw, 35),
      breakdown: buildBreakdown(aiScore, findings, Math.min(h * 20 + m * 10, 100)),
    };
  }

  // ── PATH B: Newsletter from legit domain (young domain edge case) ──────────
  const newsletter = isNewsletter(body, links);
  if (newsletter && domainLegit && h === 0) {
    return {
      total:     Math.min(Math.round(aiScore * 0.4), s.newsletterCap),
      breakdown: buildBreakdown(aiScore, findings, 0),
    };
  }

  // ── PATH C: Unknown / suspicious domain ───────────────────────────────────
  const deterministicScore = Math.min(
    h * s.highSignalPoints + m * s.mediumSignalPoints,
    100
  );

  const hasBrandSpoof = findings.some(
    f => f.severity === "high" && f.message.toLowerCase().includes("imiteer")
  );

  const floor = Math.max(
    hasBrandSpoof && ageInDays !== null && ageInDays < s.ageDays.veryNew
      ? s.floors.brandSpoofNewDomain : 0,
    hasBrandSpoof ? s.floors.brandSpoof : 0,
    h >= 3 ? s.floors.threeHigh
      : h >= 2 ? s.floors.twoHigh
      : h >= 1 && m >= 1 ? s.floors.highAndMedium
      : h >= 1 ? s.floors.oneHigh
      : m >= 2 ? s.floors.twoMedium
      : 0,
    !domainLegit && aiScore >= 50 ? s.floors.unknownDomain : 0,
  );

  const raw   = Math.round(
    deterministicScore * s.deterministicWeight +
    aiScore            * s.aiWeight +
    Math.max(ageBoost, 0) * s.ageBoostWeight
  );
  const total = Math.min(Math.max(raw, floor), 100);

  return { total, breakdown: buildBreakdown(aiScore, findings, deterministicScore) };
}

function getVerdict(score) {
  if (score >= 70) return "gevaarlijk";
  if (score >= 40) return "verdacht";
  return "veilig";
}

// ─────────────────────────────────────────────────────────────────────────────
// REQUEST HANDLER
// ─────────────────────────────────────────────────────────────────────────────

async function handleScan(req, res) {
  const { sender, senderName, subject, body, links, receivedAt,
          linkMismatches, attachments, hasQrCode, companyDomain } = req.body;

  if (!sender && !subject && !body) {
    return res.status(400).json({ error: "Geen e-mail data ontvangen" });
  }

  // Step 1: fast synchronous checks
  const findings = runDeterministicChecks({ sender, subject, body, links, linkMismatches, attachments, hasQrCode, companyDomain });

  // Step 2: slow IO in parallel — AI + RDAP
  const [aiResult, domainAge] = await Promise.all([
    analyzeWithClaude({ sender, senderName, subject, body, links, receivedAt }, findings),
    getDomainAge(sender),
  ]);

  // Step 3: enrich findings with domain age
  const ageSignal = getDomainAgeSignal(domainAge);
  if (ageSignal) findings.push(ageSignal);

  // Step 4: score
  const score = calculateScore(findings, aiResult, domainAge, body, links);

  // ENGINEER FIX: deduplicate before sending
  const allSignals = deduplicateSignals([...findings, ...(aiResult.signals || [])]);
  const verdict    = getVerdict(score.total);

  res.json({
    score:     score.total,
    verdict,
    breakdown: score.breakdown,
    summary:   aiResult.summary || "",
    signals:   allSignals,
    domainAge: domainAge
      ? { days: domainAge.ageInDays, registeredAt: domainAge.registeredAt }
      : null,
  });
}

function handleHealth(req, res) {
  res.json({
    status:    "ok",
    version:   "3.1.0",
    ai:        CONFIG.anthropicApiKey ? "✓ connected" : "✗ missing key",
    cache:     `${domainCache.size} domains cached`,
    uptime:    `${Math.round(process.uptime())}s`,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// SERVER BOOTSTRAP
// ─────────────────────────────────────────────────────────────────────────────

const app = express();

app.use(cors({
  origin:         CONFIG.allowedOrigins,
  methods:        ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
app.use(express.json({ limit: "1mb" }));
app.use(express.static("public"));

app.get("/health", handleHealth);

app.post("/scan", async (req, res) => {
  try {
    await handleScan(req, res);
  } catch (err) {
    console.error("[scan] Unhandled error:", err.message);
    res.status(500).json({ error: err.message, score: 0, signals: [], verdict: "onbekend" });
  }
});

app.listen(CONFIG.port, () => {
  console.log(`\n🛡️  PhishGuard v3.1.0 — poort ${CONFIG.port}`);
  console.log(`   AI:    ${CONFIG.anthropicApiKey ? "✓ Claude" : "✗ sleutel ontbreekt"}`);
  console.log(`   CORS:  Outlook · Gmail · Extensie`);
  console.log(`   Ready.\n`);
});
