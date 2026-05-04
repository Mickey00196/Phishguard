// PhishGuard Backend v3
// NEW: Fixed score aggregation (spoofing was only 10% bump — now full weight)
// NEW: Random domain detection (catches vfgpslja.nl style domains)

// NEW: IP reputation check via AbuseIPDB for IP-based links
// NEW: Claude prompt now explicitly told about sender email address

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ───────────────────────────────────────────────────────────────

app.use(express.json({ limit: '50kb' }));
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  methods: ['POST', 'GET']
}));
app.use('/api/', rateLimit({ windowMs: 60 * 1000, max: 60, message: { error: 'Too many requests' } }));

// ─── 1. Claude AI analysis ────────────────────────────────────────────────────

async function analyseWithClaude(sender, subject, body, linkPairs) {
  const prompt = `You are a cybersecurity expert specialising in phishing email detection.
Analyse this email carefully and return ONLY a JSON object with this exact structure:
{
  "score": <number 0-100, 100 = definitely phishing>,
  "signals": [<up to 5 short strings describing what you found>],
  "reasoning": "<one sentence summary>"
}

SENDER (full address): ${sender}
Subject: ${subject}
Body (first 1500 chars): ${body.substring(0, 1500)}
Links found: ${linkPairs.map(l => `"${l.text}" → ${l.href}`).join(' | ').substring(0, 600)}

Key things to check:
1. Does the sender domain match the brand they claim to be? (e.g. "DHL-Express" sending from vfgpslja.nl is DEFINITELY phishing)
2. Is the sender domain random-looking gibberish (random consonants, no real words)?
3. Urgency/threats language (account suspended, verify now, pakket, betaal)
4. Links pointing to unrelated domains or IP addresses
5. Brand impersonation (DHL, PostNL, ING, Rabobank, PayPal, Amazon etc.)
6. Grammar or spelling issues

IMPORTANT: A legitimate company like DHL will ALWAYS send from @dhl.com or @dhl.nl — never from a random domain like vfgpslja.nl. If you see this mismatch, score should be 85+.

Return ONLY valid JSON, no other text.`;

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': process.env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 300,
      messages: [{ role: 'user', content: prompt }]
    })
  });

  if (!response.ok) throw new Error(`Claude API error: ${response.status}`);
  const data = await response.json();
  const clean = data.content[0].text.replace(/```json|```/g, '').trim();
  return JSON.parse(clean);
}

// ─── 2. Google Safe Browsing ──────────────────────────────────────────────────

async function checkLinksWithSafeBrowsing(links) {
  if (!links || links.length === 0) return { score: 0, signals: [] };
  const uniqueLinks = [...new Set(links)].slice(0, 20);

  const response = await fetch(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFE_BROWSING_KEY}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'phishguard', clientVersion: '3.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: uniqueLinks.map(url => ({ url }))
        }
      })
    }
  );

  if (!response.ok) throw new Error(`Safe Browsing error: ${response.status}`);
  const data = await response.json();
  const matches = data.matches || [];

  if (matches.length > 0) {
    return {
      score: 95,
      signals: matches.map(m => `🔴 Google Safe Browsing: gevaarlijke link: ${m.threat.url.substring(0, 60)}`)
    };
  }
  return { score: 0, signals: ['✓ Google Safe Browsing: geen gevaarlijke links'] };
}

// ─── 3. VirusTotal ────────────────────────────────────────────────────────────

async function checkLinksWithVirusTotal(links) {
  if (!links || links.length === 0 || !process.env.VIRUSTOTAL_API_KEY) {
    return { score: 0, signals: [] };
  }

  const linksToCheck = [...new Set(links)].slice(0, 3);
  const signals = [];
  let maxScore = 0;

  for (const url of linksToCheck) {
    try {
      const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
          'x-apikey': process.env.VIRUSTOTAL_API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `url=${encodeURIComponent(url)}`
      });

      if (!submitResponse.ok) continue;
      const submitData = await submitResponse.json();
      const analysisId = submitData.data?.id;
      if (!analysisId) continue;

      await new Promise(r => setTimeout(r, 2000));

      const resultResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
      });

      if (!resultResponse.ok) continue;
      const resultData = await resultResponse.json();
      const stats = resultData.data?.attributes?.stats;

      if (stats) {
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const total = Object.values(stats).reduce((a, b) => a + b, 0);

        if (malicious > 0) {
          const score = Math.min(95, 50 + malicious * 5);
          maxScore = Math.max(maxScore, score);
          signals.push(`🔴 VirusTotal: ${malicious}/${total} engines: ${url.substring(0, 50)}`);
        } else if (suspicious > 0) {
          maxScore = Math.max(maxScore, 40);
          signals.push(`⚡ VirusTotal: ${suspicious} engines verdacht: ${url.substring(0, 50)}`);
        }
      }
    } catch (e) { /* continue */ }
  }

  if (signals.length === 0 && linksToCheck.length > 0) {
    signals.push(`✓ VirusTotal: geen flagged links`);
  }

  return { score: maxScore, signals };
}

// ─── NEW: 4. AbuseIPDB — IP reputation check — IP reputation check ─────────────────────────────────
// Free tier: 1000 checks/day. Catches phishing links that use raw IP addresses
// or domains hosted on known malicious IPs. Free key at abuseipdb.com.

async function checkIPReputation(links) {
  if (!links || links.length === 0 || !process.env.ABUSEIPDB_API_KEY) {
    return { score: 0, signals: [] };
  }

  const signals = [];
  let maxScore = 0;

  // Extract IP addresses from links (phishing often uses IPs directly)
  const ips = [];
  for (const url of links) {
    try {
      const hostname = new URL(url).hostname;
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
        ips.push(hostname);
        signals.push(`🔴 Link gebruikt IP-adres: ${hostname} (nooit legitiem voor bedrijven)`);
        maxScore = Math.max(maxScore, 80);
      }
    } catch(e) {}
  }

  // Check each IP against AbuseIPDB
  for (const ip of ips.slice(0, 3)) {
    try {
      const response = await fetch(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
        { headers: { 'Key': process.env.ABUSEIPDB_API_KEY, 'Accept': 'application/json' } }
      );

      if (!response.ok) continue;
      const data = await response.json();
      const abuseScore = data.data?.abuseConfidenceScore || 0;
      const reports = data.data?.totalReports || 0;

      if (abuseScore > 50) {
        maxScore = Math.max(maxScore, 90);
        signals.push(`🔴 AbuseIPDB: IP ${ip} heeft ${abuseScore}% abuse score (${reports} meldingen)`);
      } else if (abuseScore > 10) {
        maxScore = Math.max(maxScore, 50);
        signals.push(`⚡ AbuseIPDB: IP ${ip} heeft ${reports} meldingen`);
      }
    } catch(e) {}
  }

  return { score: maxScore, signals };
}

// ─── 6. Domain checks (improved) ─────────────────────────────────────────────

async function checkDomain(sender) {
  const signals = [];
  let score = 0;

  const domainMatch = sender.match(/@([a-zA-Z0-9.-]+)/);
  if (!domainMatch) return { score: 5, signals: ['Afzender heeft geen herkenbaar domein'] };

  const domain = domainMatch[1].toLowerCase();
  const domainBody = domain.split('.')[0];

  // ── NEW: Random domain detection ──
  // Legitimate companies never use random-looking domains
  const vowels = (domainBody.match(/[aeiou]/g) || []).length;
  const vowelRatio = vowels / domainBody.length;

  if (domainBody.length > 5 && vowelRatio < 0.2) {
    score += 70;
    signals.push(`🔴 Domein "${domain}" ziet er willekeurig gegenereerd uit (phishing indicator)`);
  } else if (domainBody.length > 7 && vowelRatio < 0.3) {
    score += 40;
    signals.push(`⚠️ Verdacht domein: "${domain}" lijkt niet op een echte bedrijfsnaam`);
  }

  // ── Brand name in sender display name but not in domain ──
  const displayName = sender.split('<')[0].toLowerCase().trim();
  const brands = [
    { name: 'dhl', domains: ['dhl.com', 'dhl.nl', 'dhl.de'] },
    { name: 'postnl', domains: ['postnl.nl', 'postnl.com'] },
    { name: 'paypal', domains: ['paypal.com', 'paypal.nl'] },
    { name: 'amazon', domains: ['amazon.com', 'amazon.nl', 'amazon.de'] },
    { name: 'microsoft', domains: ['microsoft.com', 'outlook.com', 'live.com'] },
    { name: 'google', domains: ['google.com', 'gmail.com'] },
    { name: 'apple', domains: ['apple.com', 'icloud.com'] },
    { name: 'netflix', domains: ['netflix.com'] },
    { name: 'ing', domains: ['ing.nl', 'ing.com'] },
    { name: 'rabobank', domains: ['rabobank.nl', 'rabobank.com'] },
    { name: 'abnamro', domains: ['abnamro.nl', 'abnamro.com'] },
    { name: 'bol', domains: ['bol.com'] },
    { name: 'coolblue', domains: ['coolblue.nl'] },
  ];

  for (const brand of brands) {
    if (displayName.includes(brand.name)) {
      const isLegitDomain = brand.domains.some(d => domain === d || domain.endsWith('.' + d));
      if (!isLegitDomain) {
        score += 65;
        signals.push(`🔴 "${displayName}" stuurt vanuit "${domain}" — geen officieel ${brand.name.toUpperCase()} domein`);
        break;
      }
    }
  }

  // ── Spoofing patterns (typosquatting) ──
  const spoofPatterns = [
    { brand: 'paypal',    pattern: /paypa[^l]|pay-pal|paypall/ },
    { brand: 'amazon',    pattern: /amaz[^o]n|amazoon|arnazon/ },
    { brand: 'microsoft', pattern: /micros[^o]ft|micr0soft/ },
    { brand: 'google',    pattern: /g[^o]ogle|gooogle|g00gle/ },
    { brand: 'apple',     pattern: /app1e|appIe/ },
    { brand: 'dhl',       pattern: /dh1|d-hl|dhl-express\.((?!dhl)[a-z]+)/ },
    { brand: 'irs',       pattern: /irs-[^.]+\./ }
  ];

  for (const { brand, pattern } of spoofPatterns) {
    if (pattern.test(domain)) {
      score += 50;
      signals.push(`🔴 Domein "${domain}" imiteert ${brand.toUpperCase()}`);
    }
  }

  // ── Free email provider sending as corporate ──
  const freeDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];
  if (freeDomains.includes(domain) && displayName.match(/bank|paypal|amazon|dhl|support|service/)) {
    score += 40;
    signals.push(`⚠️ Bedrijfsnaam in afzender maar verstuurd via ${domain}`);
  }

  // ── WhoisXML domain age ──
  if (process.env.WHOIS_API_KEY) {
    try {
      const whoisResp = await fetch(
        `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${process.env.WHOIS_API_KEY}&domainName=${domain}&outputFormat=JSON`
      );
      if (whoisResp.ok) {
        const whoisData = await whoisResp.json();
        const createdDate = whoisData.WhoisRecord?.registryData?.createdDate;
        if (createdDate) {
          const ageDays = (Date.now() - new Date(createdDate).getTime()) / 86400000;
          if (ageDays < 30) {
            score += 40;
            signals.push(`🔴 Domein is slechts ${Math.round(ageDays)} dagen oud`);
          } else if (ageDays < 180) {
            score += 20;
            signals.push(`⚡ Relatief nieuw domein (${Math.round(ageDays)} dagen)`);
          } else {
            signals.push(`✓ Domein is ${(ageDays / 365).toFixed(1)} jaar oud`);
          }
        }
      }
    } catch (e) { /* non-critical */ }
  }

  if (signals.length === 0) signals.push(`✓ Afzenderdomein "${domain}" ziet er normaal uit`);
  return { score: Math.min(score, 98), signals };
}

// ─── Score aggregator v3 ──────────────────────────────────────────────────────
// FIX: Spoofing was only a 10% bump before — now it's a full weighted component

// Weights: Claude 30% | Domain 25% | Spoofing 20% | Safe Browsing 13% | VirusTotal 7% | AbuseIPDB 5%
function aggregateScores(claudeResult, safeBrowsingResult, virusTotalResult, domainResult, ipResult, spoofingScore) {

  // Hard override — if Google Safe Browsing is certain, trust it fully
  if (safeBrowsingResult.score >= 95) return buildResult(95, safeBrowsingResult, virusTotalResult, domainResult, claudeResult, ipResult, spoofingScore);

  const weighted = Math.round(
    (claudeResult.score       * 0.30) +
    (domainResult.score       * 0.25) +
    (spoofingScore            * 0.20) +
    (safeBrowsingResult.score * 0.13) +
    (virusTotalResult.score   * 0.07) +
    (ipResult.score           * 0.05)
  );

  // If multiple independent checks agree it's phishing, amplify the score
  const highSignals = [claudeResult.score, domainResult.score, spoofingScore, safeBrowsingResult.score, virusTotalResult.score, ipResult.score]
    .filter(s => s >= 70).length;
  const amplified = highSignals >= 2 ? Math.min(100, weighted + 15) : weighted;

  return buildResult(amplified, safeBrowsingResult, virusTotalResult, domainResult, claudeResult, ipResult, spoofingScore);
}

function buildResult(score, safeBrowsingResult, virusTotalResult, domainResult, claudeResult, ipResult, spoofingScore) {
  const allSignals = [
    ...domainResult.signals,
    ...safeBrowsingResult.signals,
    ...virusTotalResult.signals,
    ...ipResult.signals,
    ...claudeResult.signals
  ].slice(0, 8);

  return {
    score: Math.min(100, score),
    signals: allSignals,
    reasoning: claudeResult.reasoning,
    breakdown: {
      ai: claudeResult.score,
      domain: domainResult.score,
      spoofing: spoofingScore,
      safeBrowsing: safeBrowsingResult.score,
      virusTotal: virusTotalResult.score,
      ipReputation: ipResult.score
    }
  };
}

// ─── Scan endpoint ────────────────────────────────────────────────────────────

app.post('/api/scan', async (req, res) => {
  const {
    sender, subject, body, links, linkPairs,
    spoofingScore = 0, spoofingSignals = []
  } = req.body;

  if (!sender && !subject && !body) {
    return res.status(400).json({ error: 'No email content provided' });
  }

  try {
    const [claudeResult, safeBrowsingResult, virusTotalResult, domainResult, ipResult] = await Promise.all([
      analyseWithClaude(sender || '', subject || '', body || '', linkPairs || []),
      checkLinksWithSafeBrowsing(links || []),
      checkLinksWithVirusTotal(links || []),
      checkDomain(sender || ''),
      checkIPReputation(links || [])
    ]);

    const result = aggregateScores(
      claudeResult, safeBrowsingResult, virusTotalResult, domainResult,
      ipResult, spoofingScore
    );

    // Prepend extension's local spoofing signals (highest priority — shown first)
    result.signals = [...spoofingSignals, ...result.signals].slice(0, 8);

    console.log(`[PhishGuard v3] "${sender}" — score: ${result.score}% | breakdown:`, result.breakdown);
    res.json(result);

  } catch (err) {
    console.error('[PhishGuard] Scan error:', err.message);
    res.status(500).json({ error: 'Scan failed', message: err.message });
  }
});

app.get('/health', (req, res) => res.json({ status: 'ok', version: '3.0' }));

app.listen(PORT, () => console.log(`[PhishGuard] Backend v3 on port ${PORT}`));
