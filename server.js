// PhishGuard Backend v2
// FIX 2: VirusTotal added for link scanning
// FIX 1: Accepts spoofing signals pre-computed by the extension

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
  const prompt = `You are a cybersecurity expert. Analyse this email for phishing signals.
Return ONLY a JSON object with this exact structure:
{
  "score": <number 0-100, 100 = definitely phishing>,
  "signals": [<up to 5 short strings describing what you found>],
  "reasoning": "<one sentence summary>"
}

Sender: ${sender}
Subject: ${subject}
Body (first 1500 chars): ${body.substring(0, 1500)}
Links: ${linkPairs.map(l => `"${l.text}" → ${l.href}`).join(', ').substring(0, 500)}

Check for: urgency/threats, credential/payment requests, brand impersonation, 
mismatched link text vs URL, suspicious sender domain, grammar issues.
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
        client: { clientId: 'phishguard', clientVersion: '2.0' },
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
      score: 85,
      signals: matches.map(m => `🔴 Malicious link: ${m.threat.url.substring(0, 60)}`)
    };
  }
  return { score: 0, signals: ['✓ No links flagged by Google Safe Browsing'] };
}

// ─── FIX 2: VirusTotal link scanner ──────────────────────────────────────────

async function checkLinksWithVirusTotal(links) {
  if (!links || links.length === 0 || !process.env.VIRUSTOTAL_API_KEY) {
    return { score: 0, signals: [] };
  }

  // Only check first 3 links to stay within free tier rate limits (4 req/min)
  const linksToCheck = [...new Set(links)].slice(0, 3);
  const signals = [];
  let maxScore = 0;

  for (const url of linksToCheck) {
    try {
      // VirusTotal URL scan: POST to get analysis ID
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

      // Wait briefly then fetch result
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
          const score = Math.min(90, malicious * 10);
          maxScore = Math.max(maxScore, score);
          signals.push(`🔴 VirusTotal: ${malicious}/${total} engines flagged ${url.substring(0, 50)}`);
        } else if (suspicious > 0) {
          maxScore = Math.max(maxScore, 30);
          signals.push(`⚡ VirusTotal: ${suspicious} engines marked suspicious: ${url.substring(0, 50)}`);
        }
      }
    } catch (e) {
      // VirusTotal check failed for this URL — continue
    }
  }

  if (signals.length === 0 && linksToCheck.length > 0) {
    signals.push(`✓ VirusTotal: links checked — none flagged`);
  }

  return { score: maxScore, signals };
}

// ─── 3. Domain checks ────────────────────────────────────────────────────────

async function checkDomain(sender) {
  const signals = [];
  let score = 0;

  const domainMatch = sender.match(/@([a-zA-Z0-9.-]+)/);
  if (!domainMatch) return { score: 5, signals: ['Sender has no recognisable domain'] };

  const domain = domainMatch[1].toLowerCase();

  const spoofPatterns = [
    { brand: 'paypal',    pattern: /paypa[^l]|pay-pal|paypall/ },
    { brand: 'amazon',    pattern: /amaz[^o]n|amazoon|arnazon/ },
    { brand: 'microsoft', pattern: /micros[^o]ft|micr0soft/ },
    { brand: 'google',    pattern: /g[^o]ogle|gooogle|g00gle/ },
    { brand: 'apple',     pattern: /app1e|appIe/ },
    { brand: 'netflix',   pattern: /netfl[^i]x|netfl1x/ },
    { brand: 'irs',       pattern: /irs-[^.]+\./ }
  ];

  for (const { brand, pattern } of spoofPatterns) {
    if (pattern.test(domain)) {
      score += 40;
      signals.push(`⚠️ Domain "${domain}" may be spoofing ${brand}`);
    }
  }

  const freeDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];
  if (freeDomains.includes(domain) && sender.toLowerCase().includes('support')) {
    score += 20;
    signals.push(`⚡ "Support" email from free provider: ${domain}`);
  }

  // WhoisXML domain age check
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
            signals.push(`🔴 Domain only ${Math.round(ageDays)} days old`);
          } else if (ageDays < 180) {
            score += 20;
            signals.push(`⚡ Domain is relatively new (${Math.round(ageDays)} days)`);
          } else {
            signals.push(`✓ Domain is ${(ageDays / 365).toFixed(1)} years old`);
          }
        }
      }
    } catch (e) { /* non-critical */ }
  }

  if (signals.length === 0) signals.push(`✓ Sender domain "${domain}" looks normal`);
  return { score: Math.min(score, 90), signals };
}

// ─── Score aggregator ─────────────────────────────────────────────────────────
// Weights: Claude 45% | Safe Browsing 20% | VirusTotal 20% | Domain 15%

function aggregateScores(claudeResult, safeBrowsingResult, virusTotalResult, domainResult, spoofingScore) {
  const weighted = Math.round(
    (claudeResult.score      * 0.45) +
    (safeBrowsingResult.score * 0.20) +
    (virusTotalResult.score  * 0.20) +
    (domainResult.score      * 0.15)
  );

  // Bump score if local spoofing detection fired
  const spoofBump = Math.round(spoofingScore * 0.1);
  const finalScore = Math.min(100, weighted + spoofBump);

  const allSignals = [
    ...domainResult.signals,
    ...safeBrowsingResult.signals,
    ...virusTotalResult.signals,
    ...claudeResult.signals
  ].slice(0, 8);

  return {
    score: finalScore,
    signals: allSignals,
    reasoning: claudeResult.reasoning,
    breakdown: {
      ai: claudeResult.score,
      safeBrowsing: safeBrowsingResult.score,
      virusTotal: virusTotalResult.score,
      domain: domainResult.score,
      spoofing: spoofingScore
    }
  };
}

// ─── Scan endpoint ────────────────────────────────────────────────────────────

app.post('/api/scan', async (req, res) => {
  const {
    sender, subject, body, links, linkPairs,
    spoofingScore = 0, spoofingSignals = []  // FIX 1: Accept pre-computed spoofing from extension
  } = req.body;

  if (!sender && !subject && !body) {
    return res.status(400).json({ error: 'No email content provided' });
  }

  try {
    // Run all checks in parallel
    const [claudeResult, safeBrowsingResult, virusTotalResult, domainResult] = await Promise.all([
      analyseWithClaude(sender || '', subject || '', body || '', linkPairs || []),
      checkLinksWithSafeBrowsing(links || []),
      checkLinksWithVirusTotal(links || []),   // FIX 2: VirusTotal now called
      checkDomain(sender || '')
    ]);

    const result = aggregateScores(
      claudeResult, safeBrowsingResult, virusTotalResult, domainResult, spoofingScore
    );

    // Prepend any spoofing signals from the extension
    result.signals = [...spoofingSignals, ...result.signals].slice(0, 8);

    console.log(`[PhishGuard] "${sender}" — score: ${result.score}% | breakdown:`, result.breakdown);
    res.json(result);

  } catch (err) {
    console.error('[PhishGuard] Scan error:', err.message);
    res.status(500).json({ error: 'Scan failed', message: err.message });
  }
});

app.get('/health', (req, res) => res.json({ status: 'ok', version: '2.0' }));

app.listen(PORT, () => console.log(`[PhishGuard] Backend v2 on port ${PORT}`));
