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
    postnl:          ["postnl.nl"],
    belastingdienst: ["belastingdienst.nl"],
    klm:             ["klm.com"],
    ns:              ["ns.nl"],
  },

  // ENGINEER FIX: skip RDAP for these — also skip spoofing check
  trustedEmailProviders: new Set([
    "sendgrid.net","mailchimp.com","klaviyo.com","brevo.com",
    "hubspot.com","mailgun.org","amazonses.com","sparkpostmail.com",
    "mandrillapp.com","exacttarget.com","salesforce.com","postmarkapp.com",
    "stripe.com","constantcontact.com","campaignmonitor.com",
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

  // Scoring weights
  scoring: {
    deterministicWeight: 0.4,
    aiWeight:            0.4,
    ageBoostWeight:      0.5,
    highSignalPoints:    35,
    mediumSignalPoints:  15,
    floors: { threeHigh: 85, twoHigh: 75, oneHigh: 55, twoMedium: 40 },
    ageBoosts: { veryNew: 40, young: 20, old: -15 },
    ageDays:   { veryNew: 30, young: 180, old: 730 },
    legitimateCap: 20,
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
  if (CONFIG.multiPartTlds.some(tld => domain.endsWith(tld))) return parts.slice(-3).join(".");
  return parts.slice(-2).join(".");
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

const domainCache = new Map();

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
  const event = (rdapData?.events || []).find(
    e => e.eventAction === "registration" || e.eventAction === "created"
  );
  if (!event?.eventDate) return null;
  const date = new Date(event.eventDate);
  const now  = new Date();
  if (isNaN(date) || date > now || date.getFullYear() < 1990) return null;
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
  if (cached && Date.now() - cached.timestamp < CONFIG.domainCacheTtlMs) return cached.result;

  const data    = await fetchRdapData(rootDomain);
  const regDate = data ? parseRegistrationDate(data) : null;
  const result  = regDate
    ? { ageInDays: Math.floor((Date.now() - regDate) / 86_400_000), registeredAt: regDate.toISOString(), domain: rootDomain }
    : null;

  domainCache.set(rootDomain, { result, timestamp: Date.now() });
  if (result) console.log(`[RDAP] ${rootDomain}: ${result.ageInDays}d old`);
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
      d => rootDomain === d || domain.endsWith("." + d)
    );
    if (isOfficial) continue; // legitimate sender

    // Typosquat: root domain contains brand name but isn't official
    // e.g. "dhl-tracking.com", "paypal-secure.net", "ing-alert.xyz"
    const isTyposquat = rootDomain.includes(brand) && !isOfficial;

    // Subdomain spoof: full domain contains brand as subdomain of unknown root
    // e.g. "dhl.scammer.ru" — root is "scammer.ru", but "dhl" appears before it
    const isSubdomainSpoof = domain.split(".").slice(0, -2).includes(brand);

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
  const preview = (body || "").toLowerCase().slice(0, 300);
  return CONFIG.genericGreetings.some(g => preview.includes(g))
    ? { message: "Generieke aanhef zonder persoonlijke naam", severity: "medium" }
    : null;
}

function runDeterministicChecks({ sender, subject, body, links }) {
  return [
    checkBrandSpoofing(sender),
    checkUrgency(subject, body),
    ...checkLinks(links),
    checkCredentials(body),
    checkGenericGreeting(body),
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
- Wereldwijd bekend legitiem domein → domainLegit: true, score max 20%
- Onbekend of willekeurig domein → domainLegit: false, score min 65%
- Domein imiteert een merk → domainLegit: false, score min 85%

SCOREGIDS:
0-20:  Legitiem — bekend merk, geen rode vlaggen
21-40: Waarschijnlijk veilig
41-60: Twijfelachtig
61-80: Waarschijnlijk phishing
81-100: Vrijwel zeker phishing

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
  if (!domainAge) return null;
  const { ageInDays } = domainAge;
  const { ageDays }   = CONFIG.scoring;
  if (ageInDays < ageDays.veryNew) return { message: `Domein slechts ${ageInDays} dagen oud — zeer verdacht`, severity: "high" };
  if (ageInDays < ageDays.young)   return { message: `Domein ${ageInDays} dagen oud (< 6 maanden)`, severity: "medium" };
  if (ageInDays > ageDays.old)     return { message: `Domein ${Math.floor(ageInDays / 365)} jaar oud — legitimiteitssignaal`, severity: "low" };
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

function calculateScore(findings, aiResult, domainAge) {
  const highCount   = findings.filter(f => f.severity === "high").length;
  const mediumCount = findings.filter(f => f.severity === "medium").length;
  const aiScore     = Math.min(Math.max(aiResult.aiScore || 0, 0), 100);
  const domainLegit = aiResult.domainLegit === true;
  const ageBoost    = getAgeBoost(domainAge);
  const s           = CONFIG.scoring;

  // Fast path: clearly legitimate — cap score low
  if (domainLegit && highCount === 0 && mediumCount <= 1 && ageBoost <= 0) {
    return {
      total:     Math.min(Math.round(aiScore * 0.3), s.legitimateCap),
      breakdown: buildBreakdown(aiScore, findings, 0),
    };
  }

  const deterministicScore = Math.min(
    highCount * s.highSignalPoints + mediumCount * s.mediumSignalPoints,
    100
  );

  const floor = Math.max(
    getSignalFloor(highCount, mediumCount),
    !domainLegit && aiScore >= 60 ? 65 : 0  // unknown domain floor
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
  const { sender, senderName, subject, body, links, receivedAt } = req.body;

  if (!sender && !subject && !body) {
    return res.status(400).json({ error: "Geen e-mail data ontvangen" });
  }

  // Step 1: fast synchronous checks
  const findings = runDeterministicChecks({ sender, subject, body, links });

  // Step 2: slow IO in parallel — AI + RDAP
  const [aiResult, domainAge] = await Promise.all([
    analyzeWithClaude({ sender, senderName, subject, body, links, receivedAt }, findings),
    getDomainAge(sender),
  ]);

  // Step 3: enrich findings with domain age
  const ageSignal = getDomainAgeSignal(domainAge);
  if (ageSignal) findings.push(ageSignal);

  // Step 4: score
  const score = calculateScore(findings, aiResult, domainAge);

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
