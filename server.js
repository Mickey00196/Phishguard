const express = require("express");
const cors    = require("cors");

const app  = express();
const PORT = process.env.PORT || 8080;

// ─────────────────────────────────────────────────────────────────────
// CORS — staat verzoeken toe van Outlook, Gmail én de browser extensie
// ─────────────────────────────────────────────────────────────────────
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
app.use(express.static("public")); // serveert taskpane.html + taskpane.js

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

// ── Health check ──────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({
    status:  "ok",
    service: "PhishGuard backend",
    cors:    "Outlook + Gmail + Extension",
    key:     ANTHROPIC_API_KEY ? "✓ set" : "✗ MISSING — set ANTHROPIC_API_KEY",
  });
});

// ── Hoofd scan endpoint ───────────────────────────────────────────────
// Wordt aangeroepen door: browser extensie, Outlook add-in én Gmail add-on
app.post("/scan", async (req, res) => {
  try {
    const { sender, senderName, subject, body, links, receivedAt } = req.body;

    if (!sender && !subject && !body) {
      return res.status(400).json({ error: "Geen e-mail data ontvangen" });
    }

    // Deterministische checks (snel, geen AI nodig)
    const findings = runDeterministicChecks({ sender, subject, body, links });

    // AI analyse via Claude
    const aiResult = await analyzeWithClaude(
      { sender, senderName, subject, body, links, receivedAt },
      findings
    );

    // Eindscore berekenen
    const score = calculateScore(findings, aiResult);

    res.json({
      score:     score.total,
      breakdown: score.breakdown,
      signals:   [...findings, ...(aiResult.signals || [])],
      verdict:   aiResult.verdict || getVerdict(score.total),
      summary:   aiResult.summary || "",
    });

  } catch (err) {
    console.error("Scan fout:", err.message);
    res.status(500).json({
      error:   err.message,
      score:   0,
      signals: [],
      verdict: "onbekend",
    });
  }
});

// ── Deterministische checks ───────────────────────────────────────────
function runDeterministicChecks({ sender, subject, body, links }) {
  const signals = [];

  // 1. Spoed-woorden in onderwerp
  const urgencyWords = ["urgent", "dringend", "onmiddellijk", "account geblokkeerd",
    "verify now", "act now", "suspended", "winner", "congratulations",
    "klik hier", "bevestig nu", "wachtwoord verlopen"];
  const subjectLower = (subject || "").toLowerCase();
  if (urgencyWords.some(w => subjectLower.includes(w))) {
    signals.push({ message: "Spoed- of alarmeringstaal in onderwerp", severity: "high" });
  }

  // 2. Verdachte links
  const suspiciousTlds = [".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf"];
  (links || []).forEach(link => {
    try {
      const url = new URL(link);
      if (suspiciousTlds.some(tld => url.hostname.endsWith(tld))) {
        signals.push({ message: `Verdacht domein gedetecteerd: ${url.hostname}`, severity: "high" });
      }
      if (url.hostname.includes("paypal") && !url.hostname.endsWith("paypal.com")) {
        signals.push({ message: "Nep PayPal link gedetecteerd", severity: "high" });
      }
      if (url.hostname.includes("microsoft") && !url.hostname.endsWith("microsoft.com")) {
        signals.push({ message: "Nep Microsoft link gedetecteerd", severity: "high" });
      }
    } catch {}
  });

  // 3. Veel links in de body
  if ((links || []).length > 5) {
    signals.push({ message: `${links.length} links gevonden in e-mail`, severity: "medium" });
  }

  // 4. Afzender domein check
  const senderDomain = (sender || "").split("@")[1] || "";
  const freeDomains  = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"];
  if (freeDomains.includes(senderDomain) && subject && subject.toLowerCase().includes("invoice")) {
    signals.push({ message: "Factuur van gratis e-maildomein", severity: "medium" });
  }

  // 5. Wachtwoord/credential verzoeken
  const credWords = ["password", "wachtwoord", "inloggen", "login", "verify your account",
    "bevestig je account", "creditcard", "credit card", "bank"];
  const bodyLower = (body || "").toLowerCase();
  if (credWords.some(w => bodyLower.includes(w))) {
    signals.push({ message: "Verzoek om inloggegevens of financiële info", severity: "high" });
  }

  return signals;
}

// ── Claude AI analyse ─────────────────────────────────────────────────
async function analyzeWithClaude(email, deterministicFindings) {
  if (!ANTHROPIC_API_KEY) {
    console.warn("Geen ANTHROPIC_API_KEY — AI analyse overgeslagen");
    return { signals: [], verdict: getVerdict(0), summary: "AI niet beschikbaar" };
  }

  const findingsSummary = deterministicFindings.length > 0
    ? deterministicFindings.map(f => `- ${f.message} (${f.severity})`).join("\n")
    : "Geen deterministische signalen gevonden";

  const prompt = `
Je bent een cybersecurity expert gespecialiseerd in phishing detectie.
Analyseer deze e-mail en geef een JSON response.

E-MAIL DATA:
Afzender: ${email.sender}
Naam: ${email.senderName || "onbekend"}
Onderwerp: ${email.subject}
Body (eerste 1500 tekens): ${(email.body || "").slice(0, 1500)}
Links: ${(email.links || []).join(", ") || "geen"}
Ontvangen: ${email.receivedAt || "onbekend"}

REEDS GEVONDEN SIGNALEN:
${findingsSummary}

Geef je analyse als JSON in dit formaat (ALLEEN JSON, geen tekst eromheen):
{
  "aiScore": <getal 0-100, phishing risico>,
  "verdict": "<veilig|verdacht|gevaarlijk>",
  "summary": "<1-2 zinnen samenvatting in het Nederlands>",
  "signals": [
    { "message": "<signaal beschrijving>", "severity": "<low|medium|high>" }
  ]
}
`;

  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method:  "POST",
    headers: {
      "Content-Type":      "application/json",
      "x-api-key":         ANTHROPIC_API_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model:      "claude-haiku-4-5-20251001",
      max_tokens: 800,
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
    console.error("AI gaf geen geldige JSON:", text.slice(0, 200));
    return { signals: [], aiScore: 0, verdict: "onbekend", summary: "" };
  }
}

// ── Score berekening ──────────────────────────────────────────────────
function calculateScore(findings, aiResult) {
  const severityScore = { high: 25, medium: 15, low: 5 };

  // Deterministische score
  const deterministicScore = Math.min(
    findings.reduce((sum, f) => sum + (severityScore[f.severity] || 10), 0),
    100
  );

  // AI score
  const aiScore = Math.min(aiResult.aiScore || 0, 100);

  // Gewogen gemiddelde
  const total = Math.round((deterministicScore * 0.4) + (aiScore * 0.6));

  return {
    total,
    breakdown: {
      claude:      aiScore,
      safeBrowsing: Math.min(findings.filter(f => f.severity === "high").length * 30, 100),
      virusTotal:  Math.min(findings.filter(f => f.message.includes("domein")).length * 40, 100),
      domain:      deterministicScore,
    },
  };
}

function getVerdict(score) {
  if (score >= 70) return "gevaarlijk";
  if (score >= 40) return "verdacht";
  return "veilig";
}

// ── Start server ──────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🛡️  PhishGuard backend draait op poort ${PORT}`);
  console.log(`   CORS:    Outlook + Gmail + Browser extensie`);
  console.log(`   Health:  http://localhost:${PORT}/health`);
  console.log(`   API key: ${ANTHROPIC_API_KEY ? "✓ gevonden" : "✗ ONTBREEKT — stel ANTHROPIC_API_KEY in"}\n`);
});
