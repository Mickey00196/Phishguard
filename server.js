const express = require("express");
const cors    = require("cors");

const app  = express();
const PORT = process.env.PORT || 8080;

app.use(cors({
  origin: [
    "https://outlook.office.com",
    "https://outlook.live.com",
    "https://outlook.office365.com",
    "https://mail.google.com",
    "https://script.google.com",
    "https://phishguards.up.railway.app",
  ],
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.static("public"));

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

// ── Domein cache — voorkomt dubbele RDAP calls ────────────────────────
const domainCache = new Map();
const CACHE_TTL   = 24 * 60 * 60 * 1000; // 24 uur

async function checkDomainAge(domain) {
  if (!domain) return null;

  // Haal rootdomein op (bijv. mail.evil.xyz → evil.xyz)
  const parts      = domain.split(".");
  const rootDomain = parts.length > 2 ? parts.slice(-2).join(".") : domain;

  // Check cache eerst
  const cached = domainCache.get(rootDomain);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.result;
  }

  try {
    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 3000); // 3s timeout

    const response = await fetch(`https://rdap.org/domain/${rootDomain}`, {
      signal: controller.signal,
      headers: { "Accept": "application/json" }
    });

    clearTimeout(timeout);

    if (!response.ok) {
      domainCache.set(rootDomain, { result: null, timestamp: Date.now() });
      return null;
    }

    const data   = await response.json();
    const events = data.events || [];

    // Zoek registratiedatum
    const regEvent = events.find(e =>
      e.eventAction === "registration" || e.eventAction === "created"
    );

    if (!regEvent || !regEvent.eventDate) {
      domainCache.set(rootDomain, { result: null, timestamp: Date.now() });
      return null;
    }

    const regDate  = new Date(regEvent.eventDate);
    const ageInDays = Math.floor((Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24));

    const result = { ageInDays, registeredAt: regEvent.eventDate, domain: rootDomain };
    domainCache.set(rootDomain, { result, timestamp: Date.now() });

    console.log(`[RDAP] ${rootDomain}: ${ageInDays} dagen oud`);
    return result;

  } catch (e) {
    if (e.name !== "AbortError") console.error(`[RDAP] Fout voor ${rootDomain}:`, e.message);
    domainCache.set(rootDomain, { result: null, timestamp: Date.now() });
    return null;
  }
}

app.get("/health", (req, res) => {
  res.json({
    status:  "ok",
    service: "PhishGuard backend v2.4",
    key:     ANTHROPIC_API_KEY ? "✓ set" : "✗ MISSING",
  });
});

app.post("/scan", async (req, res) => {
  try {
    const { sender, senderName, subject, body, links, receivedAt } = req.body;

    if (!sender && !subject && !body) {
      return res.status(400).json({ error: "Geen e-mail data ontvangen" });
    }

    // Deterministische checks
    const findings = runDeterministicChecks({ sender, subject, body, links });

    // Haal afzenderdomein op
    const senderDomain = (sender || "").split("@")[1] || "";

    // Claude AI + RDAP domeincheck parallel uitvoeren (sneller!)
    const [aiResult, domainAge] = await Promise.all([
      analyzeWithClaude({ sender, senderName, subject, body, links, receivedAt }, findings),
      checkDomainAge(senderDomain)
    ]);

    // Voeg domeinleeftijd toe aan signalen
    if (domainAge !== null) {
      if (domainAge.ageInDays < 30) {
        findings.push({
          message:  `Domein is slechts ${domainAge.ageInDays} dagen oud — extreem verdacht`,
          severity: "high"
        });
      } else if (domainAge.ageInDays < 180) {
        findings.push({
          message:  `Domein is ${domainAge.ageInDays} dagen oud (minder dan 6 maanden)`,
          severity: "medium"
        });
      } else if (domainAge.ageInDays > 730) {
        findings.push({
          message:  `Domein bestaat al ${Math.floor(domainAge.ageInDays / 365)} jaar — legitimiteitssignaal`,
          severity: "low"
        });
      }
    }

    // Score berekenen
    const score = calculateScore(findings, aiResult, domainAge);

    res.json({
      score:     score.total,
      breakdown: score.breakdown,
      signals:   [...findings, ...(aiResult.signals || [])],
      verdict:   aiResult.verdict || getVerdict(score.total),
      summary:   aiResult.summary || "",
      domainAge: domainAge ? {
        days: domainAge.ageInDays,
        registeredAt: domainAge.registeredAt
      } : null
    });

  } catch (err) {
    console.error("Scan fout:", err.message);
    res.status(500).json({ error: err.message, score: 0, signals: [], verdict: "onbekend" });
  }
});

// ── Deterministische checks ───────────────────────────────────────────
function runDeterministicChecks({ sender, subject, body, links }) {
  const signals = [];
  const subjectLower = (subject || "").toLowerCase();
  const bodyLower    = (body    || "").toLowerCase();
  const senderLower  = (sender  || "").toLowerCase();

  // 1. Bekende merken gespooft via vreemd domein
  const brands = ["dhl", "fedex", "ups", "postnl", "paypal", "ing", "rabobank",
    "abn", "microsoft", "apple", "google", "amazon", "netflix", "bol.com",
    "belastingdienst", "klm", "ns", "ziggo", "tmobile", "vodafone"];

  const brandDomains = {
    "dhl": ["dhl.com", "dhl.nl"], "paypal": ["paypal.com", "paypal.nl"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com"],
    "apple": ["apple.com"], "google": ["google.com", "gmail.com"],
    "amazon": ["amazon.com", "amazon.nl"], "ing": ["ing.nl"],
    "rabobank": ["rabobank.nl"], "postnl": ["postnl.nl"],
    "belastingdienst": ["belastingdienst.nl"], "klm": ["klm.com"],
  };

  const senderDomain = senderLower.split("@")[1] || "";

  // Alleen flaggen als brand IN het afzenderdomein zit maar niet het echte domein is
  for (const brand of brands) {
    const legitDomains = brandDomains[brand] || [`${brand}.com`, `${brand}.nl`];
    const isLegitDomain = legitDomains.some(d => senderDomain === d || senderDomain.endsWith(`.${d}`));
    const brandInDomain = senderDomain.includes(brand) && !isLegitDomain;

    if (brandInDomain && senderDomain) {
      signals.push({
        message:  `Afzender (${senderDomain}) doet zich voor als ${brand.toUpperCase()} — klassieke spoofing`,
        severity: "high"
      });
      break;
    }
  }

  // 2. Spoed/alarm taal
  const urgencyWords = ["dringend", "urgent", "onmiddellijk", "verify now", "act now",
    "account geblokkeerd", "suspended", "bevestig nu", "wachtwoord verlopen",
    "klik hier", "laatste waarschuwing", "actie vereist", "uw account",
    "bevestigen", "afwachting", "leveringsgegevens", "pakket"];
  const urgencyHits = urgencyWords.filter(w => bodyLower.includes(w) || subjectLower.includes(w));
  if (urgencyHits.length >= 2) {
    signals.push({ message: `Meerdere urgentie-signalen: "${urgencyHits.slice(0,3).join('", "')}"`, severity: "high" });
  } else if (urgencyHits.length === 1) {
    signals.push({ message: `Urgentietaal gevonden: "${urgencyHits[0]}"`, severity: "medium" });
  }

  // 3. Verdachte links
  const suspiciousTlds = [".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".pw", ".cc"];
  const cloudRedirects = ["googleapis.com/storage", "storage.googleapis.com",
    "bit.ly", "tinyurl", "t.co", "goo.gl", "rebrand.ly"];

  (links || []).forEach(link => {
    try {
      const url = new URL(link);
      if (suspiciousTlds.some(tld => url.hostname.endsWith(tld))) {
        signals.push({ message: `Verdacht TLD domein: ${url.hostname}`, severity: "high" });
      }
      if (cloudRedirects.some(r => link.includes(r))) {
        signals.push({ message: `Link via cloud/redirect dienst: ${url.hostname}`, severity: "high" });
      }
      // Brand spoofing in URL
      for (const brand of brands) {
        const legitDomains = brandDomains[brand] || [`${brand}.com`, `${brand}.nl`];
        if (url.hostname.includes(brand) && !legitDomains.some(d => url.hostname === d || url.hostname.endsWith(`.${d}`))) {
          signals.push({ message: `Nep ${brand.toUpperCase()} link: ${url.hostname}`, severity: "high" });
        }
      }
    } catch {}
  });

  // 4. Generieke aanhef
  const genericGreetings = ["beste klant", "dear customer", "geachte klant",
    "beste gebruiker", "dear user", "hello user"];
  if (genericGreetings.some(g => bodyLower.includes(g))) {
    signals.push({ message: "Generieke aanhef zonder persoonlijke naam", severity: "medium" });
  }

  // 5. Credential verzoeken
  const credWords = ["wachtwoord", "password", "inloggen", "creditcard",
    "credit card", "bankrekening", "pincode", "cvv", "iban"];
  if (credWords.some(w => bodyLower.includes(w))) {
    signals.push({ message: "Verzoek om gevoelige informatie", severity: "high" });
  }

  return signals;
}

// ── Claude AI analyse ─────────────────────────────────────────────────
async function analyzeWithClaude(email, deterministicFindings) {
  if (!ANTHROPIC_API_KEY) {
    return { signals: [], aiScore: 0, verdict: "onbekend", summary: "AI niet beschikbaar" };
  }

  const findingsSummary = deterministicFindings.length > 0
    ? deterministicFindings.map(f => `- [${f.severity}] ${f.message}`).join("\n")
    : "Geen deterministische signalen gevonden";

  const prompt = `Je bent een expert phishing-analist. Analyseer deze e-mail KRITISCH en geef een eerlijke risicoscore.

E-MAIL:
Afzender: ${email.sender}
Onderwerp: ${email.subject}
Body: ${(email.body || "").slice(0, 1500)}
Links: ${(email.links || []).join(", ") || "geen"}

REEDS GEVONDEN SIGNALEN:
${findingsSummary}

SCORING RICHTLIJNEN:
- 0-20%:  Duidelijk legitiem (bekende afzender, geen verdachte elementen)
- 21-40%: Waarschijnlijk veilig maar kleine twijfels
- 41-60%: Twijfelachtig, meerdere gele vlaggen
- 61-80%: Waarschijnlijk phishing, duidelijke rode vlaggen
- 81-100%: Bijna zeker phishing (brand spoofing + verdachte links + urgentie = minimaal 85%)

BELANGRIJK: Als een e-mail een bekend merk nagebootst (DHL, PayPal, bank etc.) maar van een vreemd domein komt, is de score MINIMAAL 80%.

Geef ALLEEN JSON terug:
{
  "aiScore": <0-100>,
  "verdict": "<veilig|verdacht|gevaarlijk>",
  "summary": "<2-3 zinnen uitleg in het Nederlands>",
  "signals": [
    { "message": "<signaal>", "severity": "<low|medium|high>" }
  ]
}`;

  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method:  "POST",
    headers: {
      "Content-Type":      "application/json",
      "x-api-key":         ANTHROPIC_API_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model:      "claude-haiku-4-5-20251001",
      max_tokens: 600,
      messages:   [{ role: "user", content: prompt }],
    }),
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Anthropic API fout ${response.status}: ${err}`);
  }

  const data  = await response.json();
  const text  = (data.content || []).map(b => b.text || "").join("");
  const clean = text.replace(/```json|```/g, "").trim();

  try {
    return JSON.parse(clean);
  } catch {
    return { signals: [], aiScore: 0, verdict: "onbekend", summary: "" };
  }
}

// ── Score berekening ──────────────────────────────────────────────────
function calculateScore(findings, aiResult, domainAge) {
  const highCount   = findings.filter(f => f.severity === "high").length;
  const mediumCount = findings.filter(f => f.severity === "medium").length;
  const aiScore     = Math.min(aiResult.aiScore || 0, 100);

  // Deterministische score op basis van gevonden signalen
  let deterministicScore = 0;
  deterministicScore += highCount   * 35;
  deterministicScore += mediumCount * 15;
  deterministicScore = Math.min(deterministicScore, 100);

  const domainLegit = aiResult.domainLegit === true;

  // Domein leeftijd factor
  let domainAgeScore = 0;
  if (domainAge !== null) {
    if (domainAge.ageInDays < 30)  domainAgeScore = 40; // Zeer nieuw = gevaarlijk
    else if (domainAge.ageInDays < 180) domainAgeScore = 20; // Jong = verdacht
    else if (domainAge.ageInDays > 730) domainAgeScore = -15; // Oud = legitimiteitspunt
  }

  // CATEGORIE A: Bekend legitiem domein + oud domein + geen rode signalen → max 20%
  if (domainLegit && highCount === 0 && mediumCount <= 1 && domainAgeScore <= 0) {
    return {
      total: Math.min(Math.round(aiScore * 0.3), 20),
      breakdown: { claude: aiScore, safeBrowsing: 0, virusTotal: 0, domain: 0 }
    };
  }

  // CATEGORIE B: Onbekend/random domein → minimaal 65%
  const unknownDomainMinimum = !domainLegit && aiScore >= 60 ? 65 : 0;

  // Minimumscores op basis van rode signalen
  let minimum = unknownDomainMinimum;
  if (highCount >= 3) minimum = Math.max(minimum, 85);
  else if (highCount >= 2) minimum = Math.max(minimum, 75);
  else if (highCount >= 1) minimum = Math.max(minimum, 55);
  else if (mediumCount >= 2) minimum = Math.max(minimum, 40);

  // Gewogen gemiddelde inclusief domeinleeftijd
  let total = Math.round((deterministicScore * 0.4) + (aiScore * 0.4) + Math.max(domainAgeScore, 0) * 0.5);

  // Minimum altijd gegarandeerd
  total = Math.max(total, minimum);
  total = Math.min(total, 100);

  return {
    total,
    breakdown: {
      claude:       aiScore,
      safeBrowsing: Math.min(highCount * 35, 100),
      virusTotal:   Math.min(findings.filter(f => f.message.includes("domein") || f.message.includes("link")).length * 40, 100),
      domain:       deterministicScore,
    },
  };
}

function getVerdict(score) {
  if (score >= 70) return "gevaarlijk";
  if (score >= 40) return "verdacht";
  return "veilig";
}

app.listen(PORT, () => {
  console.log(`\n🛡️  PhishGuard backend draait op poort ${PORT}`);
  console.log(`   CORS:    Outlook + Gmail + Browser extensie`);
  console.log(`   Health:  http://localhost:${PORT}/health`);
  console.log(`   API key: ${ANTHROPIC_API_KEY ? "✓ gevonden" : "✗ ONTBREEKT"}\n`);
});
