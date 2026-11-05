/*
 * ╔═══════════════════════════════════════════════════════╗
 * ║           © 2026 WELCO TECHNOLOGIES                   ║
 * ║           ALL RIGHTS RESERVED                         ║
 * ║                                                       ║
 * ║  This software is proprietary and confidential.       ║
 * ║  Unauthorized copying, modification, distribution,    ║
 * ║  or use of this software is strictly prohibited.      ║
 * ║                                                       ║
 * ║  Welco® is a registered trademark.                    ║
 * ╚═══════════════════════════════════════════════════════╝
 */

require('dotenv').config();
const fs         = require('fs');
const path       = require('path');
const crypto     = require('crypto');
const express    = require('express');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const rateLimit  = require('express-rate-limit');
const helmet     = require('helmet');
const { createClient } = require('@supabase/supabase-js');

const app      = express();
const PORT     = process.env.PORT || 3000;
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

// Render (and most hosts) sit behind a proxy. Without this every visitor looks like the same IP
// and the rate limiters below would lock everybody out together.
app.set('trust proxy', 1);

// JWT secret MUST come from the environment. If it is missing we make a random one so the
// site is still safe (but everyone has to log in again after each restart) and warn loudly.
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 16) {
  JWT_SECRET = crypto.randomBytes(48).toString('hex');
  console.warn('⚠️  JWT_SECRET is not set (or too short) in the environment. Using a temporary random secret — set JWT_SECRET on Render so logins survive restarts.');
}

process.on('unhandledRejection', function(e) { console.error('Unhandled rejection:', e && e.message ? e.message : e); });

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

// ── RATE LIMITS ──────────────────────────────────────────────────────────────
function limiter(windowMs, max, msg) {
  return rateLimit({ windowMs: windowMs, max: max, standardHeaders: true, legacyHeaders: false, message: { error: msg || 'Too many requests. Please slow down.' } });
}
const loginLimiter   = limiter(15*60*1000, 30,  'Too many login attempts. Please wait 15 minutes.');
const resetLimiter   = limiter(60*60*1000, 10,  'Too many reset attempts. Please try again in an hour.');
const otpLimiter     = limiter(10*60*1000, 10,  'Too many OTP requests. Try again in 10 minutes.');
const signupLimiter  = limiter(60*60*1000, 20,  'Too many signups from this network. Try again later.');
const aiLimiter      = limiter(60*1000,    40,  'Too many AI requests. Please wait a moment.');
const guestWriteLimiter = limiter(60*1000, 60,  'Too many requests. Please wait a moment.');
const uploadLimiter  = limiter(10*60*1000, 60,  'Too many uploads. Please wait a few minutes.');
const feedbackLimiter = limiter(10*60*1000, 30, 'Too many submissions. Please wait a few minutes.');
const apiLimiter     = limiter(60*1000,    900, 'Too many requests.');

// Per-account lockout (on top of the per-IP limits above) — stops PIN / password guessing
// even if the attacker rotates IPs. Hotel staff share one WiFi IP, so this is per account.
const failMap = new Map();
function guardCheck(key, max, windowMs) {
  const e = failMap.get(key);
  if (!e || Date.now() > e.reset) return true;
  return e.count < (max || 8);
}
function guardFail(key, windowMs) {
  const now = Date.now();
  let e = failMap.get(key);
  if (!e || now > e.reset) { e = { count: 0, reset: now + (windowMs || 15*60*1000) }; failMap.set(key, e); }
  e.count++;
}
function guardClear(key) { failMap.delete(key); }
setInterval(function() {
  const now = Date.now();
  failMap.forEach(function(v, k) { if (now > v.reset) failMap.delete(k); });
  otpStore.forEach(function(v, k) { if (now > v.expires) otpStore.delete(k); });
  otpTokens.forEach(function(v, k) { if (now > v.expires) otpTokens.delete(k); });
  otpSendLog.forEach(function(v, k) { const keep = v.filter(function(t) { return now - t < 3600000; }); if (keep.length) otpSendLog.set(k, keep); else otpSendLog.delete(k); });
}, 10*60*1000).unref();

app.use(apiLimiter);

app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ limit: '20mb', extended: true }));

// ── STATIC FILES ─────────────────────────────────────────────────────────────
// Only website files are served. Server code, config, notes and hidden files are never sent.
const ALLOWED_ROOT_FILES = /^\/(sw\.js|sw-admin\.js|sw\.admin\.js|welco-protect\.js|onesignalsdk[\w.-]*\.js|manifest[\w.-]*\.json|robots\.txt|sitemap\.xml|llms\.txt)$/i;
const BLOCKED_EXT = /\.(js|mjs|cjs|json|env|md|sql|log|yml|yaml|lock|map|txt|bak|old|ts|sh)$/i;
app.use(function(req, res, next) {
  let p = req.path;
  try { p = decodeURIComponent(req.path); } catch (e) { return res.status(400).end(); }
  const lower = p.toLowerCase();
  if (lower.split('/').some(function(seg) { return seg.startsWith('.'); }) || lower.indexOf('node_modules') !== -1 || lower.indexOf('..') !== -1) return res.status(404).end();
  if (BLOCKED_EXT.test(lower) && !ALLOWED_ROOT_FILES.test(lower)) return res.status(404).end();
  next();
});

// The admin service worker has been saved as both sw-admin.js and sw.admin.js — serve whichever exists.
app.get('/sw-admin.js', function(req, res, next) {
  const a = path.join(__dirname, 'sw-admin.js'), b = path.join(__dirname, 'sw.admin.js');
  const file = fs.existsSync(a) ? a : (fs.existsSync(b) ? b : null);
  if (!file) return next();
  res.set('Content-Type', 'application/javascript; charset=utf-8');
  res.set('Service-Worker-Allowed', '/');
  res.sendFile(file);
});

app.use(express.static(__dirname, { index: 'index.html', dotfiles: 'ignore' }));

// ── HELPERS ──────────────────────────────────────────────────────────────────
function sanitize(str) {
  if (!str) return '';
  return String(str).replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;').trim();
}
function clip(str, n) { return String(str === undefined || str === null ? '' : str).slice(0, n); }
function wrap(fn) {
  return function(req, res, next) {
    Promise.resolve(fn(req, res, next)).catch(function(e) {
      console.error('Route error', req.method, req.path, '-', e && e.message ? e.message : e);
      if (!res.headersSent) res.status(500).json({ error: 'Server error. Please try again.' });
    });
  };
}

const SALT_ROUNDS = 10;
async function hashPassword(plain) { return bcrypt.hash(plain, SALT_ROUNDS); }
// Accepts both bcrypt hashes and old plain-text values (so nobody is locked out); callers upgrade old values.
async function checkPassword(plain, hashed) {
  if (!hashed) return false;
  if (!String(hashed).startsWith('$2')) return String(plain) === String(hashed);
  try { return await bcrypt.compare(String(plain), hashed); } catch(e) { return false; }
}
function signToken(payload) { return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d', algorithm: 'HS256' }); }

function safeOwner(o) {
  if (!o) return o;
  const c = Object.assign({}, o);
  delete c.password; delete c.secret_answer; delete c.device_fingerprint;
  return c;
}

// What each kind of visitor may see of a hotel row.
const PRIVATE_HOTEL_STRIP = ['owner_password'];
const PUBLIC_HOTEL_STRIP  = ['owner_password', 'owner_email', 'owner_id', 'owner_name', 'ai_kb', 'hotel_code', 'device_fingerprint'];
function shapeHotel(h, isPrivate) {
  const o = Object.assign({}, h);
  (isPrivate ? PRIVATE_HOTEL_STRIP : PUBLIC_HOTEL_STRIP).forEach(function(k) { delete o[k]; });
  o.hotel_id = h.hotel_id || String(h.id); // never return a null hotel_id
  return o;
}

app.use(function(req, res, next) {
  const allowed = ['https://welco.onrender.com', 'http://localhost:3000', 'https://usewelco.in', 'https://www.usewelco.in'];
  const origin = req.headers.origin;
  if (origin && allowed.indexOf(origin) !== -1) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  } else if (!origin) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ── AUTH ─────────────────────────────────────────────────────────────────────
function readToken(req) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;
  try { return jwt.verify(auth.split(' ')[1], JWT_SECRET, { algorithms: ['HS256'] }); } catch (e) { return false; }
}
function verifyToken(req, res, next) {
  const u = readToken(req);
  if (u === null) return res.status(401).json({ error: 'Not authenticated. Please login again.' });
  if (u === false) return res.status(401).json({ error: 'Session expired. Please login again.' });
  req.user = u;
  next();
}
// For routes that guests may call but logged-in users get more from. A bad token is treated as "guest".
function optionalAuth(req, res, next) {
  const u = readToken(req);
  req.user = u || null;
  next();
}

// owner → manager of one or more hotels | hotel (old style hotel login) | hod | staff
function roleOf(u) {
  if (!u) return 'none';
  if (u.is_demo || u.owner_id) return 'owner';
  if (u.staff_id) return 'staff';
  if (u.hod_id) return 'hod';
  if (u.hotel_id) return 'hotel';
  return 'none';
}
const MANAGER  = ['owner', 'hotel'];
const HOD_UP   = ['owner', 'hotel', 'hod'];
const ANY_ROLE = ['owner', 'hotel', 'hod', 'staff'];
function requireRole(roles) {
  return function(req, res, next) {
    if (roles.indexOf(roleOf(req.user)) === -1) return res.status(403).json({ error: 'You do not have permission to do this.' });
    next();
  };
}
function noDemo(req, res, next) {
  if (req.user && req.user.is_demo) return res.status(403).json({ error: 'Not available in the demo.' });
  next();
}

const DEMO_HOTEL_ID = 'hotel_demo_welco';

// Which hotels does this owner own? (short cache — it is checked on every protected call)
const ownerCache = new Map();
async function ownerHotelIds(owner_id) {
  const key = String(owner_id);
  const hit = ownerCache.get(key);
  if (hit && Date.now() - hit.at < 30000) return hit.ids;
  const { data } = await supabase.from('hotels').select('id, hotel_id').eq('owner_id', owner_id);
  const ids = new Set();
  (data || []).forEach(function(h) { if (h.hotel_id) ids.add(String(h.hotel_id)); ids.add(String(h.id)); });
  ownerCache.set(key, { at: Date.now(), ids: ids });
  return ids;
}
function forgetOwner(owner_id) { ownerCache.delete(String(owner_id)); }

// THE tenant check: may this logged-in user touch this hotel's data?
async function canAccessHotel(user, hotel_id) {
  if (!user || hotel_id === undefined || hotel_id === null || String(hotel_id) === '') return false;
  const hid = String(hotel_id);
  if (user.is_demo) return hid === DEMO_HOTEL_ID;
  if (user.owner_id) return (await ownerHotelIds(user.owner_id)).has(hid);
  if (user.hotel_id) return String(user.hotel_id) === hid;
  return false;
}
// Check the hotel named in params / body / query
function hotelAccess(where) {
  return wrap(async function(req, res, next) {
    const id = where === 'params' ? req.params.hotel_id : where === 'body' ? (req.body || {}).hotel_id : req.query.hotel_id;
    if (!id) return res.status(400).json({ error: 'hotel_id required.' });
    if (!(await canAccessHotel(req.user, id))) return res.status(403).json({ error: 'Access denied for this hotel.' });
    next();
  });
}
// Check the hotel that owns row :id in a table (rooms, staff, hod, requests...)
function resourceAccess(table) {
  return wrap(async function(req, res, next) {
    const id = req.params.id;
    if (!id || String(id).length > 40) return res.status(400).json({ error: 'Invalid id.' });
    const { data, error } = await supabase.from(table).select('*').eq('id', id).maybeSingle();
    if (error || !data) return res.status(404).json({ error: 'Not found.' });
    if (!(await canAccessHotel(req.user, data.hotel_id))) return res.status(403).json({ error: 'Access denied.' });
    req.resource = data;
    next();
  });
}

async function findHotel(id) {
  id = String(id === undefined || id === null ? '' : id).trim();
  if (!id || id.length > 100) return null;
  let { data } = await supabase.from('hotels').select('*').eq('hotel_id', id).maybeSingle();
  if (!data && /^\d+$/.test(id)) {
    const r = await supabase.from('hotels').select('*').eq('id', Number(id)).maybeSingle();
    data = r.data;
  }
  return data || null;
}

async function uniqueHotelCode(name) {
  let base = String(name || '').toUpperCase().replace(/[^A-Z]/g, '').substring(0, 3);
  while (base.length < 3) base += 'X';
  for (let i = 0; i < 12; i++) {
    const code = base + (100 + crypto.randomInt(900));
    const { data } = await supabase.from('hotels').select('id').eq('hotel_code', code).limit(1);
    if (!data || !data.length) return code;
  }
  return base + (1000 + crypto.randomInt(9000));
}
async function uniqueStaffId(hotelCode) {
  for (let i = 0; i < 12; i++) {
    const sid = (hotelCode || 'WLC') + '-' + (1000 + crypto.randomInt(9000));
    const { data } = await supabase.from('staff').select('id').eq('staff_id', sid).limit(1);
    if (!data || !data.length) return sid;
  }
  return (hotelCode || 'WLC') + '-' + Date.now().toString().slice(-6);
}

// Guest ID-proof text is only for Front Desk / management — hide it from other departments.
function redactIds(row, user) {
  const role = roleOf(user);
  const dept = String(user && user.dept || '');
  if ((role === 'staff' || role === 'hod') && dept !== 'Front Desk' && row && typeof row.message === 'string') {
    const i = row.message.indexOf('ID Proofs');
    if (i !== -1) return Object.assign({}, row, { message: row.message.slice(0, i).trim() + '\n🪪 ID proofs hidden (Front Desk only)' });
  }
  return row;
}

// ── GROQ AI ─────────────────────────────────────────────────────────────────
const GROQ_KEY = process.env.GROQ_API_KEY;
const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';

async function askGemini(prompt) {
  const response = await fetch(GROQ_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + GROQ_KEY
    },
    body: JSON.stringify({
      model: 'llama-3.1-8b-instant',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.7,
      max_tokens: 512
    })
  });
  const json = await response.json();
  if (json.error) {
    console.error('Groq API error:', JSON.stringify(json.error));
    throw new Error(json.error.message || 'Groq error');
  }
  const text = json.choices?.[0]?.message?.content || '';
  if (!text) {
    console.error('Groq empty response:', JSON.stringify(json));
    throw new Error('Empty response from Groq');
  }
  return text.trim();
}

// 1. AI GUEST CHATBOT (guests use this without logging in, so it is rate limited and size capped)
app.post('/ai/chat', aiLimiter, async (req, res) => {
  let { message, hotel_name, room_number, hotel_id } = req.body || {};
  message     = clip(message, 500).replace(/"/g, "'").trim();
  hotel_name  = clip(hotel_name, 100).replace(/"/g, "'");
  room_number = clip(room_number, 20);
  hotel_id    = clip(hotel_id, 100);
  if (!message) return res.status(400).json({ error: 'Message required' });
  try {
    let kb = {};
    let hotelCity = '';
    if (hotel_id) {
      const { data: hotelData } = await supabase
        .from('hotels')
        .select('ai_kb, name, city')
        .eq('hotel_id', hotel_id)
        .single();
      if (hotelData) {
        kb = hotelData.ai_kb || {};
        hotelCity = hotelData.city || '';
      }
    }

    const faqContext = (kb.faqs && kb.faqs.length > 0)
      ? '\n\nFAQs:\n' + kb.faqs.map(f => `Q: ${f.q}\nA: ${f.a}`).join('\n\n')
      : '';

    const kbContext = [
      kb.wifi_name  ? `WiFi Network Name: ${kb.wifi_name}` : '',
      kb.wifi       ? `WiFi Password: ${kb.wifi}` : '',
      kb.checkin    ? `Check-in time: ${kb.checkin}` : '',
      kb.checkout   ? `Check-out time: ${kb.checkout}` : '',
      kb.facilities ? `Facilities & Timings: ${kb.facilities}` : '',
      kb.activities ? `Activities & Experiences (with prices): ${kb.activities}` : '',
      kb.restaurant ? `Restaurant & Food (timings & prices): ${kb.restaurant}` : '',
      kb.transport  ? `Transport & Location: ${kb.transport}` : '',
      kb.contact    ? `Reception contact: ${kb.contact}` : '',
      kb.emergency  ? `Emergency contact: ${kb.emergency}` : '',
      kb.extra      ? `Other hotel info: ${kb.extra}` : '',
    ].filter(Boolean).join('\n') + faqContext;

    const prompt = `You are a smart hotel concierge AI for "${hotel_name || 'our hotel'}" in ${hotelCity || 'India'}, Room ${room_number || '?'}.

=== HOTEL KNOWLEDGE BASE ===
${kbContext || 'No specific hotel info provided yet — give general helpful answers.'}

=== CITY GUIDE ===
Hotel is located in ${hotelCity || 'India'}. You know popular places to visit, local food, shopping markets, transport options, weather, culture and festivals in this city. Share this knowledge freely when guests ask about the city, places to visit, local food, shopping, etc.

=== GUEST MESSAGE ===
"${message}"
(May be in any language — detect and reply in the SAME language)

=== DECISION RULES — FOLLOW STRICTLY ===

SET needs_staff = TRUE and route to correct department ONLY for these physical service requests:
- Water bottles, towels, pillow, blanket, toiletries, bedsheet → Housekeeping
- Room cleaning, housekeeping service → Housekeeping  
- Food order, breakfast, chai, coffee, tea, snacks, room service, ice → Room Service
- AC not working, TV issue, light/electricity problem, WiFi not connecting, plumbing, door lock → Maintenance
- Wake up call, luggage help, taxi/cab booking, late checkout, room upgrade, billing → Front Desk

SET needs_staff = FALSE for ALL information requests:
- WiFi password or network name → answer from KB
- Checkout/checkin time → answer from KB
- Restaurant timings or menu → answer from KB
- Pool, spa, gym timings → answer from KB
- Activities and prices → answer from KB
- Places to visit in the city → answer from city knowledge
- Local food recommendations → answer from city knowledge
- Shopping markets → answer from city knowledge
- How to reach somewhere → answer from city knowledge
- Any general question about hotel or city → answer directly

=== IMPORTANT ===
- When needs_staff is TRUE: reply should be a SHORT confirmation like "Your [item] is on the way! 🙏" 
- When needs_staff is FALSE: reply should be a DETAILED, helpful answer
- Never give WiFi info when guest asks for water/towels/food
- Never ignore a service request — always route it to staff
- task field = short English description for staff (e.g. "2 water bottles to Room 101")

Respond in JSON only — no markdown, no extra text:
{
  "reply": "Response to guest in their language",
  "needs_staff": true or false,
  "department": "Housekeeping or Room Service or Maintenance or Front Desk or null",
  "task": "Short English task for staff e.g. '2 water bottles Room 101' or null",
  "priority": "normal or urgent",
  "english_message": "English translation of guest message"
}`;

    const raw = await askGemini(prompt);
    const clean = raw.replace(/```json|```/g, '').trim();

    // Extract JSON even if AI adds extra text
    const jsonMatch = clean.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error('No JSON in response');

    res.json(JSON.parse(jsonMatch[0]));
  } catch(e) {
    console.error('AI chat error:', e.message);
    // Smart fallback — detect if it's a service request
    const lower = message.toLowerCase();
    const serviceKeywords = ['water','towel','pillow','clean','food','chai','coffee','tea','breakfast','ac ','wifi not','tv ','light ','door','luggage','taxi','checkout','wake'];
    const isService = serviceKeywords.some(k => lower.includes(k));
    if (isService) {
      res.json({
        reply: "Your request has been sent to our team! We will attend to you shortly. 🙏",
        needs_staff: true,
        department: lower.includes('food')||lower.includes('chai')||lower.includes('coffee')||lower.includes('tea')||lower.includes('breakfast')||lower.includes('water') ? 'Room Service' : 'Front Desk',
        task: message.substring(0, 80) + ' — Room ' + (room_number || '?'),
        priority: 'normal',
        english_message: message
      });
    } else {
      res.json({
        reply: "I'm here to help! You can ask me about the hotel, facilities, local places to visit, or request any service. 😊",
        needs_staff: false,
        department: null,
        task: null,
        priority: 'normal',
        english_message: message
      });
    }
  }
});

// 2. SMART UPSELLING
app.post('/ai/upsell', aiLimiter, async (req, res) => {
  const hotel_name = clip(req.body.hotel_name, 100).replace(/"/g, "'");
  const room_number = clip(req.body.room_number, 20);
  const time_of_day = clip(req.body.time_of_day, 20);
  const recent_requests = clip(JSON.stringify(req.body.recent_requests || []), 1000);
  try {
    const prompt = `You are a hotel upselling AI for "${hotel_name}". Room: ${room_number}, Time: ${time_of_day || 'afternoon'}, Recent requests: ${recent_requests}.
Suggest 2 upsell offers in JSON only:
{"offers":[{"emoji":"🍳","title":"Short title","desc":"One line","price":"₹XXX"},{"emoji":"💆","title":"Short title","desc":"One line","price":"₹XXX"}]}
Make relevant to time of day and Indian hotel. Prices in INR.`;
    const raw = await askGemini(prompt);
    const clean = raw.replace(/```json|```/g, '').trim();
    res.json(JSON.parse(clean));
  } catch(e) {
    res.json({ offers: [{ emoji:'🍳', title:'Breakfast in Bed', desc:'Fresh Indian breakfast to your room', price:'₹350' },{ emoji:'💆', title:'Spa Package', desc:'60 min relaxing massage', price:'₹1,200' }]});
  }
});

// 3. AI ANALYTICS (owner / HOD only)
app.post('/ai/analytics', verifyToken, requireRole(HOD_UP), aiLimiter, async (req, res) => {
  const question = clip(req.body.question, 500).replace(/"/g, "'");
  const hotel_name = clip(req.body.hotel_name, 100).replace(/"/g, "'");
  if (!question) return res.status(400).json({ error: 'Question required' });
  try {
    const summary = clip(JSON.stringify(req.body.requests_summary || {}), 4000);
    const prompt = `You are a hotel analytics AI for "${hotel_name}". Data: ${summary}. Owner question: "${question}". Answer in 2-3 sentences, plain English, actionable.`;
    const answer = await askGemini(prompt);
    res.json({ answer });
  } catch(e) {
    res.json({ answer: 'Unable to analyze right now. Please try again.' });
  }
});

// 4. SMART ROUTING
app.post('/ai/route', aiLimiter, async (req, res) => {
  const message = clip(req.body.message, 500).replace(/"/g, "'");
  if (!message) return res.status(400).json({ error: 'Message required' });
  try {
    const prompt = `Classify this hotel guest request. Message: "${message}". Reply JSON only: {"department":"Housekeeping|Room Service|Maintenance|Front Desk","priority":"normal|urgent","english":"English translation"}. Urgent=safety/medical/no power/flooding.`;
    const raw = await askGemini(prompt);
    const clean = raw.replace(/```json|```/g, '').trim();
    res.json(JSON.parse(clean));
  } catch(e) {
    res.json({ department: 'Front Desk', priority: 'normal', english: message });
  }
});

// 5. STAFF RESPONSE SUGGESTIONS (staff only)
app.post('/ai/suggest-response', verifyToken, requireRole(ANY_ROLE), aiLimiter, async (req, res) => {
  const request_message = clip(req.body.request_message, 500).replace(/"/g, "'");
  const department = clip(req.body.department, 40);
  const staff_name = clip(req.body.staff_name, 60);
  const hotel_name = clip(req.body.hotel_name, 100);
  try {
    const prompt = `Hotel staff response helper. Hotel: ${hotel_name}, Staff: ${staff_name}, Dept: ${department}. Guest request: "${request_message}". Write 3 short warm responses in JSON only: {"suggestions":["~10 word friendly response","~10 word professional response","~12 word response with ETA"]}`;
    const raw = await askGemini(prompt);
    const clean = raw.replace(/```json|```/g, '').trim();
    res.json(JSON.parse(clean));
  } catch(e) {
    res.json({ suggestions: ['On my way! Will be there shortly 🙏','Noted! Taking care of this right away.','Your request is accepted. Ready in 5 minutes!']});
  }
});

app.get('/health', (req,res) => res.json({ status:'ok', ts:Date.now() }));

// ── SUPABASE STORAGE UPLOAD ──────────────────────────────────────────────────
// Guests upload ID proofs here without logging in, so it is strict: images only, size capped,
// random unguessable file names, never overwrites an existing file.
function sniffImage(buf) {
  if (buf.length > 12 && buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) return { type: 'image/jpeg', ext: 'jpg' };
  if (buf.length > 12 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47) return { type: 'image/png', ext: 'png' };
  if (buf.length > 12 && buf.slice(0, 4).toString() === 'RIFF' && buf.slice(8, 12).toString() === 'WEBP') return { type: 'image/webp', ext: 'webp' };
  return null;
}
const MAX_UPLOAD_BYTES = 6 * 1024 * 1024;

app.post('/upload', uploadLimiter, wrap(async (req, res) => {
  const base64 = req.body && req.body.base64;
  if (!base64 || typeof base64 !== 'string') return res.status(400).json({ error: 'base64 required' });
  if (base64.length > MAX_UPLOAD_BYTES * 1.4) return res.status(413).json({ error: 'Image is too large.' });

  const m = base64.match(/^data:[A-Za-z0-9.+\/-]+;base64,(.+)$/);
  const buffer = Buffer.from(m ? m[1] : base64, 'base64');
  if (!buffer.length || buffer.length > MAX_UPLOAD_BYTES) return res.status(413).json({ error: 'Image is too large.' });
  const kind = sniffImage(buffer);
  if (!kind) return res.status(400).json({ error: 'Only JPG, PNG or WEBP images are allowed.' });

  // Optional hotel folder so files are grouped per hotel (letters/numbers only)
  const hotelFolder = clip(req.body.hotel_id, 60).replace(/[^a-zA-Z0-9_-]/g, '');
  const filePath = 'guest-ids/' + (hotelFolder ? hotelFolder + '/' : '') + crypto.randomBytes(16).toString('hex') + '.' + kind.ext;

  const { error } = await supabase.storage.from('welco-ids').upload(filePath, buffer, { contentType: kind.type, upsert: false });
  if (error) {
    console.error('Supabase storage upload error:', error.message);
    return res.status(500).json({ error: 'Upload failed. Please try again.' });
  }
  const { data: urlData } = supabase.storage.from('welco-ids').getPublicUrl(filePath);
  res.json({ success: true, url: urlData.publicUrl, path: filePath });
}));

// Staff/HOD/owner ask for short-lived viewing links for guest ID photos (works whether the
// storage bucket is public or private). A link is only given if the photo belongs to a
// request of a hotel the caller may access.
app.post('/id-photos/sign', verifyToken, requireRole(HOD_UP.concat(['staff'])), hotelAccess('body'), wrap(async (req, res) => {
  const role = roleOf(req.user);
  if ((role === 'staff' || role === 'hod') && String(req.user.dept || '') !== 'Front Desk') {
    return res.status(403).json({ error: 'ID photos are visible to Front Desk and management only.' });
  }
  const urls = Array.isArray(req.body.urls) ? req.body.urls.slice(0, 12) : [];
  const out = {};
  for (const u of urls) {
    const s = String(u || '');
    const i = s.indexOf('/welco-ids/');
    const p = i === -1 ? '' : decodeURIComponent(s.slice(i + '/welco-ids/'.length).split('?')[0]);
    if (!p || p.indexOf('..') !== -1 || p.indexOf('guest-ids/') !== 0) continue;
    // the photo must be mentioned in one of this hotel's requests
    const { data: found } = await supabase.from('requests').select('id').eq('hotel_id', String(req.body.hotel_id)).ilike('message', '%' + p.replace(/[%_\\]/g, '\\$&') + '%').limit(1);
    if (!found || !found.length) continue;
    const { data: signed, error } = await supabase.storage.from('welco-ids').createSignedUrl(p, 60 * 60);
    if (!error && signed && signed.signedUrl) out[s] = signed.signedUrl;
  }
  res.json({ urls: out });
}));

// ── DEMO LOGIN ─────────────────────────────────────────────────────────────

async function ensureDemoHotel() {
  const { data: existing } = await supabase.from('hotels').select('*').eq('hotel_id', DEMO_HOTEL_ID).maybeSingle();
  if (existing) return existing;
  const { data: hotel } = await supabase.from('hotels').insert([{
    hotel_id: DEMO_HOTEL_ID, name: 'Welco Demo Hotel', city: 'Udaipur',
    owner_id: null, colour: '#005f73', emoji: '🏨', hotel_code: 'DEMO001',
    owner_email: 'demo@welco.app', owner_password: '',
  }]).select().single();
  if (!hotel) return null;
  const rooms = [];
  for (let i = 1; i <= 15; i++) rooms.push({ hotel_id: DEMO_HOTEL_ID, room_number: String(100+i), floor: Math.ceil(i/5), is_active: true });
  await supabase.from('rooms').insert(rooms);
  await supabase.from('staff').insert([
    { hotel_id: DEMO_HOTEL_ID, name: 'Ramesh', pin: '1111', staff_id: 'DEMO001-1111', department: 'Housekeeping', is_active: true },
    { hotel_id: DEMO_HOTEL_ID, name: 'Sunil',  pin: '2222', staff_id: 'DEMO001-2222', department: 'Room Service',  is_active: true },
    { hotel_id: DEMO_HOTEL_ID, name: 'Vikram', pin: '3333', staff_id: 'DEMO001-3333', department: 'Maintenance',   is_active: true },
    { hotel_id: DEMO_HOTEL_ID, name: 'Priya',  pin: '4444', staff_id: 'DEMO001-4444', department: 'Front Desk',    is_active: true },
  ]);
  await supabase.from('hod').insert([{ hotel_id: DEMO_HOTEL_ID, name: 'Meena', department: 'Housekeeping', pin: '0000', is_active: true }]);
  const now = new Date();
  await supabase.from('requests').insert([
    { hotel_id: DEMO_HOTEL_ID, room_number: '101', category: 'Housekeeping', message: 'Extra towels and pillow please', status: 'pending',     sla_minutes: 10, created_at: new Date(now - 5*60000).toISOString() },
    { hotel_id: DEMO_HOTEL_ID, room_number: '103', category: 'Room Service',  message: 'Chai aur biscuit chahiye',       status: 'in_progress', sla_minutes: 15, claimed_by: 'Sunil', claimed_at: new Date(now - 2*60000).toISOString(), created_at: new Date(now - 8*60000).toISOString() },
    { hotel_id: DEMO_HOTEL_ID, room_number: '107', category: 'Maintenance',   message: 'AC is not cooling properly',     status: 'pending',     sla_minutes: 20, created_at: new Date(now - 3*60000).toISOString() },
    { hotel_id: DEMO_HOTEL_ID, room_number: '110', category: 'Front Desk',    message: 'Airport taxi for 6 AM tomorrow', status: 'done',        sla_minutes: 5,  claimed_by: 'Priya', feedback_rating: 5, feedback_comments: 'Very prompt!', created_at: new Date(now - 60*60000).toISOString(), completed_at: new Date(now - 55*60000).toISOString() },
    { hotel_id: DEMO_HOTEL_ID, room_number: '102', category: 'Housekeeping', message: 'Room cleaning required',          status: 'done',        sla_minutes: 30, claimed_by: 'Ramesh', feedback_rating: 4, created_at: new Date(now - 120*60000).toISOString(), completed_at: new Date(now - 100*60000).toISOString() },
    { hotel_id: DEMO_HOTEL_ID, room_number: '105', category: 'Room Service',  message: 'Two water bottles please',       status: 'pending',     sla_minutes: 5,  created_at: new Date(now - 1*60000).toISOString() },
  ]);
  return hotel;
}

app.get('/demo/login', wrap(async (req,res) => {
  const hotel = await ensureDemoHotel();
  if (!hotel) return res.status(500).json({ error: 'Demo hotel unavailable.' });
  const token = signToken({ owner_id: 'demo', email: 'demo@welco.app', is_demo: true });
  res.json({ hotel: shapeHotel(hotel, true), hotels: [shapeHotel(hotel, true)], token, is_demo: true });
}));

// Resetting the demo needs a demo session (no longer open to the whole internet)
app.get('/demo/reset', verifyToken, wrap(async (req,res) => {
  if (!req.user.is_demo) return res.status(403).json({ error: 'Demo sessions only.' });
  await supabase.from('requests').delete().eq('hotel_id', DEMO_HOTEL_ID);
  await supabase.from('staff').delete().eq('hotel_id', DEMO_HOTEL_ID);
  await supabase.from('hod').delete().eq('hotel_id', DEMO_HOTEL_ID);
  await supabase.from('rooms').delete().eq('hotel_id', DEMO_HOTEL_ID);
  await supabase.from('hotels').delete().eq('hotel_id', DEMO_HOTEL_ID);
  const hotel = await ensureDemoHotel();
  res.json({ success: true, hotel: hotel ? shapeHotel(hotel, true) : null });
}));

// ════════════════════════════════════════════
// AUTH — OTP SIGNUP
// ════════════════════════════════════════════

// In-memory stores
const otpStore   = new Map(); // phone -> {otp, expires, attempts}
const otpTokens  = new Map(); // verified token -> {phone, expires}
const otpSendLog = new Map(); // phone -> [timestamps]  (stops SMS bombing a number)

// Fast2SMS API for OTP
async function sendSMSOTP(phone, otp) {
  const FAST2SMS_KEY = process.env.FAST2SMS_KEY || '';
  if (!FAST2SMS_KEY) return false;
  try {
    const message = 'Your Welco verification code is ' + otp + '. Valid for 10 minutes. Do not share with anyone.';
    const url = 'https://www.fast2sms.com/dev/bulkV2?authorization=' + encodeURIComponent(FAST2SMS_KEY)
      + '&route=q'
      + '&message=' + encodeURIComponent(message)
      + '&language=english'
      + '&flash=0'
      + '&numbers=' + encodeURIComponent(phone);

    const res = await fetch(url, { method: 'GET' });
    const data = await res.json();
    if (data.return === true) return true;
    console.error('Fast2SMS quick route failed:', JSON.stringify(data));

    const res2 = await fetch('https://www.fast2sms.com/dev/bulkV2', {
      method: 'POST',
      headers: { 'authorization': FAST2SMS_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        route: 'v3',
        sender_id: 'WELCOO',
        message: 'Your Welco OTP is ' + otp + '. Valid for 10 mins.',
        language: 'english',
        flash: 0,
        numbers: phone
      })
    });
    const data2 = await res2.json();
    if (data2.return !== true) console.error('Fast2SMS v3 failed:', JSON.stringify(data2));
    return data2.return === true;
  } catch(e) {
    console.error('SMS error:', e.message);
    return false;
  }
}

function generateOTP() { return String(crypto.randomInt(100000, 1000000)); }
function generateToken(length) { return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length); }
function otpSendAllowed(phone) {
  const now = Date.now();
  const arr = (otpSendLog.get(phone) || []).filter(function(t) { return now - t < 3600000; });
  if (arr.length >= 3) return false;                        // max 3 SMS per number per hour
  if (arr.length && now - arr[arr.length - 1] < 45000) return false; // and 45 seconds apart
  arr.push(now);
  otpSendLog.set(phone, arr);
  return true;
}

// STEP 1: SEND OTP
app.post('/auth/send-otp', otpLimiter, wrap(async (req, res) => {
  const phone = String(req.body.phone || '').replace(/\D/g, '').slice(-10);
  if (!phone || phone.length !== 10) return res.status(400).json({ error: 'Please enter a valid 10-digit mobile number.' });

  const { data: existingOwner } = await supabase.from('owners').select('id').eq('phone', phone).maybeSingle();
  if (existingOwner) return res.status(400).json({ error: 'This mobile number is already registered. Please login instead.' });

  if (!otpSendAllowed(phone)) return res.status(429).json({ error: 'Please wait a minute before asking for another OTP (max 3 per hour).' });

  const otp = generateOTP();
  otpStore.set(phone, { otp: otp, expires: Date.now() + 10 * 60 * 1000, attempts: 0 });

  const sent = await sendSMSOTP(phone, otp);
  if (!sent) {
    // Testing only: set DEV_SHOW_OTP=true on the server to see the code on screen. Never leave it on.
    if (process.env.DEV_SHOW_OTP === 'true') return res.json({ success: true, dev_otp: otp, message: 'SMS not sent — dev mode.' });
    otpStore.delete(phone);
    console.error('OTP SMS could not be sent to', phone, '- check FAST2SMS_KEY and Fast2SMS balance.');
    return res.status(503).json({ error: 'We could not send the SMS right now. Please try again in a minute, or WhatsApp us on +91 88245 46343.' });
  }
  res.json({ success: true, message: 'OTP sent to +91' + phone });
}));

// STEP 2: VERIFY OTP
app.post('/auth/verify-otp', otpLimiter, wrap(async (req, res) => {
  const phone = String(req.body.phone || '').replace(/\D/g, '').slice(-10);
  const otp = String(req.body.otp || '').trim();
  if (!phone || !otp) return res.status(400).json({ error: 'Phone and OTP required.' });

  const stored = otpStore.get(phone);
  if (!stored) return res.status(400).json({ error: 'OTP expired or not found. Please request a new one.' });
  if (Date.now() > stored.expires) {
    otpStore.delete(phone);
    return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
  }
  stored.attempts = (stored.attempts || 0) + 1;
  if (stored.attempts > 5) {
    otpStore.delete(phone);
    return res.status(400).json({ error: 'Too many wrong attempts. Please request a new OTP.' });
  }
  if (stored.otp !== otp) {
    return res.status(400).json({ error: 'Incorrect OTP. ' + (5 - stored.attempts) + ' attempts remaining.' });
  }

  otpStore.delete(phone);
  const token = generateToken(48);
  otpTokens.set(token, { phone: phone, expires: Date.now() + 30 * 60 * 1000 });
  res.json({ success: true, token: token });
}));

// STEP 3: COMPLETE SIGNUP
app.post('/auth/signup-complete', signupLimiter, wrap(async (req, res) => {
  const body = req.body || {};
  const name = clip(body.name, 100).trim(), email = clip(body.email, 150).trim().toLowerCase();
  const hotel_name = clip(body.hotel_name, 100).trim(), password = String(body.password || ''), phone = String(body.phone || '');
  const otp_token = String(body.otp_token || '');

  if (!name || !email || !hotel_name || !password || !phone || !otp_token) return res.status(400).json({ error: 'All fields required.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Please enter a valid email.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short.' });
  if (password.length > 72) return res.status(400).json({ error: 'Password is too long (max 72 characters).' });

  const tokenData = otpTokens.get(otp_token);
  if (!tokenData) return res.status(400).json({ error: 'Session expired. Please start over.' });
  if (Date.now() > tokenData.expires) {
    otpTokens.delete(otp_token);
    return res.status(400).json({ error: 'Session expired. Please start over.' });
  }
  const cleanPhone = phone.replace(/\D/g, '').slice(-10);
  if (tokenData.phone !== cleanPhone) return res.status(400).json({ error: 'Phone mismatch. Please start over.' });
  otpTokens.delete(otp_token);

  const { data: existingPhone } = await supabase.from('owners').select('id').eq('phone', cleanPhone).maybeSingle();
  if (existingPhone) return res.status(400).json({ error: 'This phone number is already registered.' });
  const { data: existingEmail } = await supabase.from('owners').select('id').eq('email', email).maybeSingle();
  if (existingEmail) return res.status(400).json({ error: 'This email is already registered.' });

  const hashed = await hashPassword(password);
  const ownerData = {
    name: sanitize(name),
    email: email,
    password: hashed,
    phone: cleanPhone,
    group_name: sanitize(hotel_name),
    plan: 'free'
  };
  if (body.fingerprint) ownerData.device_fingerprint = clip(body.fingerprint, 100);

  let { data: owner, error: ownerErr } = await supabase.from('owners').insert([ownerData]).select().single();
  if (ownerErr && /device_fingerprint|plan/.test(ownerErr.message || '')) {
    // optional columns do not exist in this database — retry without them
    delete ownerData.device_fingerprint; delete ownerData.plan;
    const retry = await supabase.from('owners').insert([ownerData]).select().single();
    owner = retry.data; ownerErr = retry.error;
  }
  if (ownerErr) { console.error('signup owner insert:', ownerErr.message); return res.status(500).json({ error: 'Could not create your account. Please try again.' }); }

  const hotelCode = await uniqueHotelCode(hotel_name);
  const { data: hotel, error: hotelErr } = await supabase.from('hotels').insert([{
    name: sanitize(hotel_name),
    owner_id: owner.id,
    hotel_code: hotelCode,
    colour: '#005f73',
    emoji: '🏨',
    owner_email: email
  }]).select().single();
  if (hotelErr) { console.error('signup hotel insert:', hotelErr.message); return res.status(500).json({ error: 'Could not create your hotel. Please try again.' }); }

  const rooms = Array.from({ length: 10 }, function(_, i) { return { hotel_id: hotel.id, room_number: String(i + 1), floor: 'Floor 1', room_status: 'vacant' }; });
  await supabase.from('rooms').insert(rooms);
  forgetOwner(owner.id);

  const token = signToken({ owner_id: owner.id, email: owner.email });
  const hotelForAdmin = {
    hotel_id: hotel.id,
    name: hotel.name,
    city: hotel.city || '',
    colour: hotel.colour || '#005f73',
    emoji: hotel.emoji || '🏨',
    hotel_code: hotel.hotel_code,
    owner_id: owner.id,
    owner_email: owner.email
  };
  res.json({ success: true, owner: safeOwner(owner), hotel: hotelForAdmin, token: token });
}));

// ── OWNER / HOTEL LOGIN ──────────────────────────────────────────────────────
const loginHandler = wrap(async (req, res) => {
  const emailRaw = sanitize(clip(req.body.email, 150)), password = String(req.body.password || '');
  const email = emailRaw.toLowerCase();
  if (!email || !password) return res.status(400).json({ error: 'Please enter email and password.' });
  const key = 'login:' + email;
  if (!guardCheck(key, 8)) return res.status(429).json({ error: 'Too many wrong attempts for this account. Please wait 15 minutes and try again.' });

  let { data: owner } = await supabase.from('owners').select('*').eq('email', email).maybeSingle();
  if (!owner && emailRaw !== email) { const r = await supabase.from('owners').select('*').eq('email', emailRaw).maybeSingle(); owner = r.data; }

  if (owner) {
    if (!(await checkPassword(password, owner.password))) { guardFail(key); return res.status(401).json({ error: 'Invalid email or password.' }); }
    guardClear(key);
    if (!String(owner.password).startsWith('$2')) { const h = await hashPassword(password); await supabase.from('owners').update({ password: h }).eq('id', owner.id); }
    const { data: hotels } = await supabase.from('hotels').select('*').eq('owner_id', owner.id).order('created_at', { ascending: true });
    const list = (hotels || []).map(function(h) { return shapeHotel(h, true); });
    forgetOwner(owner.id);
    return res.json({ owner: safeOwner(owner), hotels: list, hotel: list[0] || null, token: signToken({ owner_id: owner.id, email: owner.email }) });
  }

  // old-style hotel login (hotel row holds the email + password)
  const { data: hotel } = await supabase.from('hotels').select('*').eq('owner_email', email).maybeSingle();
  if (!hotel || !(await checkPassword(password, hotel.owner_password))) { guardFail(key); return res.status(401).json({ error: 'Invalid email or password.' }); }
  guardClear(key);
  const shaped = shapeHotel(hotel, true);
  res.json({ hotel: shaped, hotels: [shaped], token: signToken({ hotel_id: shaped.hotel_id, email: email }) });
});
app.post('/login', loginLimiter, loginHandler);
app.post('/owner/login', loginLimiter, loginHandler);

// ADD HOTEL (owner only — the owner comes from the login token, never from the request body)
app.post('/owner/add-hotel', verifyToken, requireRole(['owner']), noDemo, wrap(async (req, res) => {
  const owner_id = req.user.owner_id;
  const hotelName = sanitize(clip(req.body.hotelName, 100)), city = sanitize(clip(req.body.city, 80));
  const roomCount = Math.max(0, parseInt(req.body.roomCount) || 0);
  const colour = /^#[0-9a-fA-F]{3,8}$/.test(String(req.body.colour || '')) ? req.body.colour : '#0a9396';
  const emoji = sanitize(clip(req.body.emoji || '🏨', 8));
  if (!hotelName) return res.status(400).json({ error: 'hotelName required.' });

  const hotel_id = 'hotel_' + hotelName.toLowerCase().replace(/[^a-z0-9]/g, '').substring(0, 10) + '_' + crypto.randomBytes(3).toString('hex');
  const hotel_code = await uniqueHotelCode(hotelName);
  const { data: hotel, error } = await supabase.from('hotels').insert([{ hotel_id, name: hotelName, city, owner_id, colour, emoji, hotel_code, owner_email: '', owner_password: '' }]).select().single();
  if (error) { console.error('add-hotel:', error.message); return res.status(500).json({ error: 'Could not add the hotel. Please try again.' }); }
  forgetOwner(owner_id);
  if (roomCount > 0) {
    const rooms = [];
    for (let i = 1; i <= Math.min(roomCount, 500); i++) rooms.push({ hotel_id, room_number: String(i), floor: Math.ceil(i / 10), is_active: true });
    await supabase.from('rooms').insert(rooms);
  }
  res.json({ hotel: shapeHotel(hotel, true) });
}));

// SECRET QUESTION / RESET PASSWORD (only works for accounts that set a secret answer; heavily throttled)
app.get('/owner/secret-question', resetLimiter, wrap(async (req, res) => {
  const email = sanitize(clip(req.query.email, 150)).toLowerCase();
  if (!email) return res.status(400).json({ error: 'Email required.' });
  const { data: owner } = await supabase.from('owners').select('id, secret_answer').eq('email', email).maybeSingle();
  if (!owner) return res.status(404).json({ error: 'No account found.' });
  if (!owner.secret_answer) return res.status(400).json({ error: 'No security question set.' });
  res.json({ found: true, question: 'mother' });
}));

app.post('/owner/reset-password', resetLimiter, wrap(async (req, res) => {
  const email = sanitize(clip(req.body.email, 150)).toLowerCase();
  const answer = sanitize(clip(req.body.secret_answer, 100)).toLowerCase().trim();
  const new_password = String(req.body.new_password || '');
  if (!email || !answer || !new_password) return res.status(400).json({ error: 'All fields required.' });
  if (new_password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  if (new_password.length > 72) return res.status(400).json({ error: 'Password is too long (max 72 characters).' });

  const key = 'reset:' + email;
  if (!guardCheck(key, 5)) return res.status(429).json({ error: 'Too many wrong answers. Please wait 15 minutes.' });
  const { data: owner } = await supabase.from('owners').select('*').eq('email', email).maybeSingle();
  if (!owner || !owner.secret_answer) { guardFail(key); return res.status(404).json({ error: 'Account not found.' }); }
  const stored = String(owner.secret_answer).toLowerCase().trim();
  const ok = stored.startsWith('$2') ? await checkPassword(answer, owner.secret_answer) : stored === answer;
  if (!ok) { guardFail(key); return res.status(401).json({ error: 'Wrong answer.' }); }
  guardClear(key);
  const update = { password: await hashPassword(new_password) };
  if (!stored.startsWith('$2')) update.secret_answer = await hashPassword(answer); // upgrade the old plain-text answer
  await supabase.from('owners').update(update).eq('email', email);
  res.json({ success: true });
}));

// ── HOTELS ───────────────────────────────────────────────────────────────────
// Public: ?hotel_id=X returns that one hotel's guest-facing info (name, colours, logo, options).
// Logged in and allowed: also gets the private fields. Without hotel_id a logged-in owner gets their own hotels.
app.get('/hotels', optionalAuth, wrap(async (req, res) => {
  const wanted = req.query.hotel_id ? String(req.query.hotel_id) : '';
  if (wanted) {
    const h = await findHotel(wanted);
    if (!h) return res.json([]);
    const priv = (await canAccessHotel(req.user, h.hotel_id || h.id)) || (await canAccessHotel(req.user, h.id));
    return res.json([shapeHotel(h, priv)]);
  }
  const role = roleOf(req.user);
  if (role === 'owner' && !req.user.is_demo) {
    const { data } = await supabase.from('hotels').select('*').eq('owner_id', req.user.owner_id).order('created_at', { ascending: true });
    return res.json((data || []).map(function(h) { return shapeHotel(h, true); }));
  }
  if (role === 'owner' && req.user.is_demo) {
    const h = await findHotel(DEMO_HOTEL_ID);
    return res.json(h ? [shapeHotel(h, true)] : []);
  }
  if (req.user && req.user.hotel_id) {
    const h = await findHotel(req.user.hotel_id);
    return res.json(h ? [shapeHotel(h, true)] : []);
  }
  res.json([]); // the full hotel list is never public
}));

app.post('/hotels/:hotel_id/dept-guest-options', verifyToken, requireRole(HOD_UP), hotelAccess('params'), wrap(async (req, res) => {
  const { dept_guest_options } = req.body;
  if (dept_guest_options === undefined || JSON.stringify(dept_guest_options).length > 100000) return res.status(400).json({ error: 'Invalid options.' });
  const { data, error } = await supabase.from('hotels').update({ dept_guest_options }).eq('hotel_id', req.params.hotel_id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(shapeHotel(data, true));
}));
app.post('/hotels/:hotel_id/guest-options', verifyToken, requireRole(MANAGER), hotelAccess('params'), wrap(async (req, res) => {
  const { guest_options } = req.body;
  if (guest_options === undefined || JSON.stringify(guest_options).length > 100000) return res.status(400).json({ error: 'Invalid options.' });
  const { data, error } = await supabase.from('hotels').update({ guest_options }).eq('hotel_id', req.params.hotel_id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(shapeHotel(data, true));
}));
// Only the fields that are sent get changed (before, saving settings wiped the AI knowledge base and emoji).
app.post('/hotels/:hotel_id/update', verifyToken, requireRole(MANAGER), hotelAccess('params'), wrap(async (req, res) => {
  const b = req.body || {}, update = {};
  if (b.name !== undefined) { update.name = sanitize(clip(b.name, 100)); if (!update.name) return res.status(400).json({ error: 'Hotel name cannot be empty.' }); }
  if (b.city !== undefined) update.city = sanitize(clip(b.city, 80));
  if (b.colour !== undefined) { if (!/^#[0-9a-fA-F]{3,8}$/.test(String(b.colour))) return res.status(400).json({ error: 'Invalid colour.' }); update.colour = b.colour; }
  if (b.emoji !== undefined && b.emoji !== '') update.emoji = sanitize(clip(b.emoji, 8));
  if (b.logo_url !== undefined) {
    const l = b.logo_url;
    if (l && !(/^https:\/\//.test(l) || /^data:image\/(png|jpeg|jpg|webp|gif);base64,/.test(l))) return res.status(400).json({ error: 'Logo must be an image.' });
    if (l && String(l).length > 4000000) return res.status(413).json({ error: 'Logo is too large.' });
    update.logo_url = l || null;
  }
  if (b.ai_kb !== undefined) { if (JSON.stringify(b.ai_kb || {}).length > 60000) return res.status(413).json({ error: 'Knowledge base is too large.' }); update.ai_kb = b.ai_kb || {}; }
  if (!Object.keys(update).length) return res.status(400).json({ error: 'Nothing to update.' });
  const { data, error } = await supabase.from('hotels').update(update).eq('hotel_id', req.params.hotel_id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(shapeHotel(data, true));
}));

app.post('/hotels/:hotel_id/kb', verifyToken, requireRole(HOD_UP), hotelAccess('params'), wrap(async (req, res) => {
  const hotel_id = req.params.hotel_id;
  const { data: hotelData } = await supabase.from('hotels').select('ai_kb').eq('hotel_id', hotel_id).single();
  const currentKb = (hotelData && hotelData.ai_kb) || {};
  const newKb = Object.assign({}, currentKb, req.body.ai_kb || {});
  if (JSON.stringify(newKb).length > 60000) return res.status(413).json({ error: 'Knowledge base is too large.' });
  const { data, error } = await supabase.from('hotels').update({ ai_kb: newKb }).eq('hotel_id', hotel_id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, hotel: shapeHotel(data, true) });
}));

app.post('/hotels/:hotel_id/photos', verifyToken, requireRole(MANAGER), hotelAccess('params'), wrap(async (req, res) => {
  const hotel_photos = Array.isArray(req.body.hotel_photos) ? req.body.hotel_photos.slice(0, 20) : [];
  const { data, error } = await supabase.from('hotels').update({ hotel_photos }).eq('hotel_id', req.params.hotel_id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, hotel: shapeHotel(data, true) });
}));

// ── ROOMS ────────────────────────────────────────────────────────────────────
app.get('/rooms', verifyToken, requireRole(ANY_ROLE), hotelAccess('query'), wrap(async (req, res) => {
  const { data, error } = await supabase.from('rooms').select('*').eq('hotel_id', req.query.hotel_id);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
}));
app.post('/rooms', verifyToken, requireRole(HOD_UP), hotelAccess('body'), wrap(async (req, res) => {
  const hotel_id = req.body.hotel_id, room_number = sanitize(clip(req.body.room_number, 20)), floor = parseInt(req.body.floor) || 1, is_active = req.body.is_active !== false;
  if (!room_number) return res.status(400).json({ error: 'Room number required.' });
  const { data, error } = await supabase.from('rooms').insert([{ hotel_id, room_number, floor, is_active }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
}));
app.post('/rooms/:id/status', verifyToken, requireRole(ANY_ROLE), resourceAccess('rooms'), wrap(async (req, res) => {
  const validStatuses = ['occupied', 'vacant', 'dirty', 'clean', 'out_of_order'];
  const { status } = req.body;
  if (!status || !validStatuses.includes(status)) return res.status(400).json({ error: 'Invalid status' });
  const { error } = await supabase.from('rooms').update({ room_status: status }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, status });
}));
app.delete('/rooms/:id', verifyToken, requireRole(HOD_UP), resourceAccess('rooms'), wrap(async (req, res) => {
  const { error } = await supabase.from('rooms').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
}));

// ── STAFF ────────────────────────────────────────────────────────────────────
// PINs are shown to the admin / HOD so they can hand them to staff, so they stay readable — but only
// to a logged-in admin or HOD of the SAME hotel. They are never public.
app.get('/staff', verifyToken, requireRole(HOD_UP), hotelAccess('query'), wrap(async (req, res) => {
  let query = supabase.from('staff').select('*').eq('hotel_id', req.query.hotel_id);
  if (req.query.department) query = query.eq('department', req.query.department);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
}));
app.post('/staff', verifyToken, requireRole(HOD_UP), hotelAccess('body'), wrap(async (req, res) => {
  const hotel_id = req.body.hotel_id, name = sanitize(clip(req.body.name, 60)), pin = String(req.body.pin || '').trim(), department = sanitize(clip(req.body.department || 'General', 40));
  if (!name) return res.status(400).json({ error: 'Name required.' });
  if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be exactly 4 digits.' });
  // an HOD can only add staff to their own department
  if (roleOf(req.user) === 'hod' && String(req.user.dept) !== department) return res.status(403).json({ error: 'You can only add staff to your own department.' });
  const hotelData = await findHotel(hotel_id);
  const staff_id = await uniqueStaffId(hotelData ? hotelData.hotel_code : 'WLC');
  const { data, error } = await supabase.from('staff').insert([{ hotel_id, name, pin, department, staff_id, is_active: true }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
}));
app.post('/staff/:id/duty', verifyToken, requireRole(ANY_ROLE), resourceAccess('staff'), wrap(async (req, res) => {
  if (roleOf(req.user) === 'staff' && String(req.user.staff_id) !== String(req.params.id)) return res.status(403).json({ error: 'You can only change your own duty status.' });
  const is_on_duty = !!req.body.is_on_duty, now = new Date().toISOString(), update = { is_on_duty };
  if (is_on_duty) update.clocked_in_at = now; else update.clocked_out_at = now;
  const { data, error } = await supabase.from('staff').update(update).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  const out = Object.assign({}, data); if (roleOf(req.user) === 'staff') delete out.pin;
  res.json(out);
}));
app.delete('/staff/:id', verifyToken, requireRole(HOD_UP), resourceAccess('staff'), wrap(async (req, res) => {
  if (roleOf(req.user) === 'hod' && String(req.resource.department) !== String(req.user.dept)) return res.status(403).json({ error: 'You can only remove staff from your own department.' });
  const { error } = await supabase.from('staff').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
}));
app.post('/staff/verify', loginLimiter, wrap(async (req, res) => {
  const staff_id = sanitize(clip(req.body.staff_id, 60)), pin = String(req.body.pin || '').trim(), hotel_id = clip(req.body.hotel_id, 100), name = sanitize(clip(req.body.name, 60));
  if (!pin || (!staff_id && !(hotel_id && name))) return res.status(401).json({ error: 'Invalid Staff ID or PIN.' });
  const key = 'staff:' + (staff_id || (hotel_id + ':' + name)).toLowerCase();
  if (!guardCheck(key, 8)) return res.status(429).json({ error: 'Too many wrong attempts. Please wait 15 minutes or ask your manager.' });

  let query = supabase.from('staff').select('*').eq('is_active', true);
  if (staff_id) query = query.eq('staff_id', staff_id); else query = query.eq('hotel_id', hotel_id).eq('name', name);
  const { data: rows } = await query;
  let found = null;
  for (const r of (rows || [])) { if (await checkPassword(pin, r.pin)) { found = r; break; } }
  if (!found) { guardFail(key); return res.status(401).json({ error: 'Invalid Staff ID or PIN.' }); }
  guardClear(key);
  const token = signToken({ staff_id: found.id, hotel_id: found.hotel_id, dept: found.department });
  const safe = Object.assign({}, found); delete safe.pin;
  res.json({ success: true, staff: safe, token });
}));

// ── HOD ──────────────────────────────────────────────────────────────────────
app.get('/hod', verifyToken, requireRole(HOD_UP), hotelAccess('query'), wrap(async (req, res) => {
  const { data, error } = await supabase.from('hod').select('*').eq('hotel_id', req.query.hotel_id);
  if (error) return res.status(500).json({ error: error.message });
  // an HOD never sees other HODs' PINs
  if (roleOf(req.user) === 'hod') return res.json((data || []).map(function(h) { const c = Object.assign({}, h); if (String(h.id) !== String(req.user.hod_id)) delete c.pin; return c; }));
  res.json(data);
}));
app.post('/hod', verifyToken, requireRole(MANAGER), hotelAccess('body'), wrap(async (req, res) => {
  const hotel_id = req.body.hotel_id, name = sanitize(clip(req.body.name, 60)), department = sanitize(clip(req.body.department, 40)), pin = String(req.body.pin || '').trim();
  if (!hotel_id || !name || !department || !pin) return res.status(400).json({ error: 'All fields required.' });
  if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be exactly 4 digits.' });
  const { data: existing } = await supabase.from('hod').select('id').eq('hotel_id', hotel_id).eq('department', department).eq('is_active', true).maybeSingle();
  if (existing) return res.status(400).json({ error: 'HOD already exists for ' + department + '. Remove first.' });
  const { data, error } = await supabase.from('hod').insert([{ hotel_id, name, department, pin, is_active: true }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
}));
app.post('/hod/:id/permissions', verifyToken, requireRole(MANAGER), resourceAccess('hod'), wrap(async (req, res) => {
  const { permissions } = req.body;
  if (permissions === undefined || JSON.stringify(permissions).length > 5000) return res.status(400).json({ error: 'Invalid permissions.' });
  const { data, error } = await supabase.from('hod').update({ permissions }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
}));
app.delete('/hod/:id', verifyToken, requireRole(MANAGER), resourceAccess('hod'), wrap(async (req, res) => {
  const { error } = await supabase.from('hod').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
}));

app.post('/hod/verify', loginLimiter, wrap(async (req, res) => {
  const hotel_code = clip(req.body.hotel_code, 30).trim().toUpperCase();
  const name = clip(req.body.name, 60).trim();
  const pin = String(req.body.pin || '').trim();
  if (!hotel_code || !/^[A-Z0-9]+$/.test(hotel_code)) return res.status(400).json({ error: 'Hotel code required.' });
  if (!name) return res.status(400).json({ error: 'Name required.' });
  if (!pin) return res.status(400).json({ error: 'PIN required.' });

  const key = 'hod:' + hotel_code + ':' + name.toLowerCase();
  if (!guardCheck(key, 8)) return res.status(429).json({ error: 'Too many wrong attempts. Please wait 15 minutes or ask your admin.' });

  const { data: matchingHotels, error: hErr } = await supabase.from('hotels').select('*').ilike('hotel_code', hotel_code);
  if (hErr) return res.status(500).json({ error: 'Could not load hotel.' });
  if (!matchingHotels || !matchingHotels.length) { guardFail(key); return res.status(401).json({ error: 'Hotel code not found. Check the code from your admin.' }); }

  let foundHod = null, foundHotel = null, nameFoundAnywhere = false;
  for (const h of matchingHotels) {
    const ids = [h.hotel_id, h.id].filter(function(v) { return v !== null && v !== undefined; }).map(String);
    const { data: hods } = await supabase.from('hod').select('*').in('hotel_id', ids);
    const nameMatches = (hods || []).filter(function(x) { return x.is_active !== false && (x.name || '').toLowerCase().trim() === name.toLowerCase(); });
    for (const m of nameMatches) {
      nameFoundAnywhere = true;
      if (await checkPassword(pin, String(m.pin).trim())) { foundHod = m; foundHotel = h; break; }
    }
    if (foundHod) break;
  }

  if (!foundHod) {
    guardFail(key);
    if (nameFoundAnywhere) return res.status(401).json({ error: 'Wrong PIN. Please check with your admin.' });
    return res.status(401).json({ error: 'No HODs set up for this hotel yet. Ask admin to add you.' });
  }
  guardClear(key);
  const hotelId = foundHotel.hotel_id || String(foundHotel.id);
  const token = signToken({ hod_id: foundHod.id, hotel_id: hotelId, dept: foundHod.department });
  const safeHod = Object.assign({}, foundHod); delete safeHod.pin;
  const hotelOut = shapeHotel(foundHotel, true);
  res.json({ success: true, hod: Object.assign({}, safeHod, { hotel: hotelOut }), token });
}));

// ── REQUESTS ─────────────────────────────────────────────────────────────────
// Full request lists (with guest details) are for logged-in staff / HOD / admin of that hotel only.
app.get('/requests', verifyToken, requireRole(ANY_ROLE), hotelAccess('query'), wrap(async (req, res) => {
  const hotel_id = req.query.hotel_id;
  const user = req.user;

  if (req.query.all === 'true') {
    const { data, error } = await supabase.from('requests').select('*').eq('hotel_id', hotel_id).order('created_at', { ascending: false }).limit(20000);
    if (error) return res.status(500).json({ error: error.message });
    return res.json((data || []).map(function(r) { return redactIds(r, user); }));
  }

  let days = parseInt(req.query.days) || 7;
  if (days > 90) days = 90;
  if (days < 1) days = 1;
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - days);
  const cutoffISO = cutoff.toISOString();

  const recentQuery = supabase.from('requests').select('*').eq('hotel_id', hotel_id).order('created_at', { ascending: false }).gte('created_at', cutoffISO);
  const activeQuery = supabase.from('requests').select('*').eq('hotel_id', hotel_id).in('status', ['pending', 'in_progress']).lt('created_at', cutoffISO).order('created_at', { ascending: false });
  const [recentResult, activeResult] = await Promise.all([recentQuery, activeQuery]);
  if (recentResult.error) return res.status(500).json({ error: recentResult.error.message });

  const recentData = recentResult.data || [];
  const activeData = activeResult.data || [];
  const recentIds = new Set(recentData.map(function(r) { return r.id; }));
  const merged = recentData.concat(activeData.filter(function(r) { return !recentIds.has(r.id); }));
  merged.sort(function(a, b) { return new Date(b.created_at) - new Date(a.created_at); });
  res.json(merged.map(function(r) { return redactIds(r, user); }));
}));

// A guest checking on THEIR OWN request: only the status, nothing else
app.get('/requests/:id/status', wrap(async (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid id.' });
  const { data } = await supabase.from('requests').select('id, status, claimed_by, feedback_rating, category').eq('id', id).maybeSingle();
  if (!data) return res.status(404).json({ error: 'Not found.' });
  res.json(data);
}));

// ── PUSH NOTIFICATIONS (OneSignal) ──
// Needs ONESIGNAL_REST_API_KEY in Render environment variables.
const ONESIGNAL_APP_ID  = process.env.ONESIGNAL_APP_ID || '20e9e447-6ecd-488d-bdf2-c9c2e81bdee9';
const ONESIGNAL_API_KEY = process.env.ONESIGNAL_REST_API_KEY || '';
const PUBLIC_URL        = process.env.PUBLIC_URL || 'https://usewelco.in';

async function oneSignalSend(externalIds, title, body) {
  if (!ONESIGNAL_API_KEY) return { ok:false, error:'ONESIGNAL_REST_API_KEY is not set on the server.' };
  if (!externalIds || !externalIds.length) return { ok:false, error:'No staff to notify.' };
  try {
    const r = await fetch('https://api.onesignal.com/notifications', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': (ONESIGNAL_API_KEY.startsWith('os_v2') ? 'Key ' : 'Basic ') + ONESIGNAL_API_KEY
      },
      body: JSON.stringify({
        app_id: ONESIGNAL_APP_ID,
        target_channel: 'push',
        include_aliases: { external_id: externalIds.map(String) },
        headings: { en: title },
        contents: { en: body },
        url: PUBLIC_URL + '/staff.html',
        priority: 10,
        ttl: 3600
      })
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok || (data.errors && data.errors.length)) {
      console.error('OneSignal error:', r.status, JSON.stringify(data));
      return { ok:false, status:r.status, data };
    }
    return { ok:true, status:r.status, data };
  } catch (e) {
    console.error('OneSignal request failed:', e.message);
    return { ok:false, error:e.message };
  }
}

// Alert on-duty staff of the matching department (or everyone on duty if that department has nobody on duty)
async function notifyStaffOfRequest(hotel_id, category, room_number, message) {
  try {
    const { data: onDuty, error } = await supabase.from('staff').select('id, department')
      .eq('hotel_id', String(hotel_id)).eq('is_on_duty', true).eq('is_active', true);
    if (error || !onDuty || !onDuty.length) return;
    const cat = String(category || '').toLowerCase();
    let targets = onDuty.filter(s => String(s.department || '').toLowerCase() === cat);
    if (!targets.length) targets = onDuty;
    // never put guest ID details into a lock-screen notification
    const shortMsg = String(message || 'No details').split('🪪')[0].trim().slice(0, 140) || 'New request';
    await oneSignalSend(
      targets.map(s => s.id),
      '🔔 New Request — Room ' + (room_number || '?'),
      (category || 'General') + ': ' + shortMsg
    );
  } catch (e) { console.error('notifyStaffOfRequest failed:', e.message); }
}

// Staff can send themselves a test notification to check their phone is set up
app.post('/push/test', verifyToken, requireRole(['staff']), wrap(async (req, res) => {
  const result = await oneSignalSend([req.user.staff_id], '🔔 Welco test', 'Notifications are working on this device!');
  res.json(result);
}));

// Guests create requests without logging in (so: rate limited, hotel must exist, sizes capped)
app.post('/requests', guestWriteLimiter, wrap(async (req, res) => {
  const hotel_id = clip(req.body.hotel_id, 100);
  const room_number = sanitize(clip(req.body.room_number, 30));
  const category = sanitize(clip(req.body.category, 40));
  const message = sanitize(clip(req.body.message, 6000));
  const sla_minutes = Math.min(1440, Math.max(1, parseInt(req.body.sla_minutes) || 15));
  if (!hotel_id || !message) return res.status(400).json({ error: 'hotel_id and message required.' });
  if (!(await findHotel(hotel_id))) return res.status(404).json({ error: 'Hotel not found.' });

  const { data, error } = await supabase.from('requests').insert([{ hotel_id, room_number, category, message, status: 'pending', sla_minutes }]).select().single();
  if (error) { console.error('request insert:', error.message); return res.status(500).json({ error: 'Could not send your request. Please try again.' }); }
  res.json(data);
  notifyStaffOfRequest(hotel_id, category, room_number, message); // fire-and-forget, never blocks the guest
}));
app.post('/requests/:id/claim', verifyToken, requireRole(ANY_ROLE), resourceAccess('requests'), wrap(async (req, res) => {
  const claimed_by = sanitize(clip(req.body.claimed_by, 60));
  const { data, error } = await supabase.from('requests').update({ status: 'in_progress', claimed_by, claimed_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(redactIds(data, req.user));
}));
app.post('/requests/:id/complete', verifyToken, requireRole(ANY_ROLE), resourceAccess('requests'), wrap(async (req, res) => {
  const { data, error } = await supabase.from('requests').update({ status: 'done', completed_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(redactIds(data, req.user));
}));
// Guest rates a finished request (one rating per request — it cannot be overwritten later)
app.post('/requests/:id/feedback', feedbackLimiter, wrap(async (req, res) => {
  const id = parseInt(req.params.id);
  const rating = parseInt(req.body.rating), feedback_comments = sanitize(clip(req.body.feedback_comments, 1000));
  if (!id) return res.status(400).json({ error: 'Invalid id.' });
  if (!(rating >= 1 && rating <= 5)) return res.status(400).json({ error: 'Rating must be 1-5.' });
  const { data: row } = await supabase.from('requests').select('id, status, feedback_rating').eq('id', id).maybeSingle();
  if (!row) return res.status(404).json({ error: 'Not found.' });
  if (row.feedback_rating) return res.json({ id: row.id, feedback_rating: row.feedback_rating });
  const { data, error } = await supabase.from('requests').update({ feedback_rating: rating, feedback_comments }).eq('id', id).select('id, feedback_rating').single();
  if (error) return res.status(500).json({ error: 'Could not save feedback.' });
  res.json(data);
}));

// ── CHECKOUT FEEDBACK ────────────────────────────────────────────────────────
app.post('/checkout-feedback', feedbackLimiter, wrap(async (req, res) => {
  const hotel_id = clip(req.body.hotel_id, 100), rating = parseInt(req.body.rating);
  if (!hotel_id || !(rating >= 1 && rating <= 5)) return res.status(400).json({ error: 'hotel_id and a rating of 1-5 are required.' });
  if (!(await findHotel(hotel_id))) return res.status(404).json({ error: 'Hotel not found.' });
  const { data, error } = await supabase.from('checkout_reviews').insert([{
    hotel_id,
    room_number: sanitize(clip(req.body.room_number, 30)),
    guest_name:  sanitize(clip(req.body.guest_name, 100)),
    guest_email: sanitize(clip(req.body.guest_email, 150)),
    rating:      rating,
    review:      sanitize(clip(req.body.review, 2000))
  }]).select('id').single();
  if (error) {
    // report the failure honestly (before it said "success" and the review was silently lost)
    console.error('checkout_reviews insert error:', error.message);
    return res.status(500).json({ error: 'Could not save your review. Please try again.' });
  }
  res.json({ success: true, id: data && data.id });
}));

// GET CHECKOUT REVIEWS — for admin panel
app.get('/checkout-reviews', verifyToken, requireRole(HOD_UP), hotelAccess('query'), wrap(async (req, res) => {
  const { data, error } = await supabase.from('checkout_reviews').select('*').eq('hotel_id', req.query.hotel_id).order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
}));

// ── ANNOUNCEMENTS ────────────────────────────────────────────────────────────
// Guests see only the active announcements of the hotel they are in; staff/HOD/admin see all of theirs.
app.get('/announcements', optionalAuth, wrap(async (req, res) => {
  const hotel_id = req.query.hotel_id;
  if (!hotel_id) return res.status(400).json({ error: 'hotel_id required.' });
  const priv = await canAccessHotel(req.user, hotel_id);
  let query = supabase.from('announcements').select(priv ? '*' : 'id, message, created_at, is_active').eq('hotel_id', hotel_id).order('created_at', { ascending: false });
  if (!priv) query = query.eq('is_active', true);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
}));
app.post('/announcements', verifyToken, requireRole(HOD_UP), hotelAccess('body'), wrap(async (req, res) => {
  const hotel_id = req.body.hotel_id, message = sanitize(clip(req.body.message, 500));
  if (!message) return res.status(400).json({ error: 'Message required.' });
  await supabase.from('announcements').update({ is_active: false }).eq('hotel_id', hotel_id);
  const { data, error } = await supabase.from('announcements').insert([{ hotel_id, message, is_active: true }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
}));
app.delete('/announcements/:id', verifyToken, requireRole(HOD_UP), resourceAccess('announcements'), wrap(async (req, res) => {
  const { error } = await supabase.from('announcements').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
}));
app.post('/announcements/:id/toggle', verifyToken, requireRole(HOD_UP), resourceAccess('announcements'), wrap(async (req, res) => {
  const is_active = !!req.body.is_active;
  const { data, error } = await supabase.from('announcements').update({ is_active }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
}));

// ── MAINTENANCE ──────────────────────────────────────────────────────────────
app.get('/maintenance', verifyToken, requireRole(ANY_ROLE), hotelAccess('query'), wrap(async (req, res) => {
  let query = supabase.from('maintenance_tasks').select('*').eq('is_active', true).eq('hotel_id', req.query.hotel_id).order('next_due', { ascending: true });
  if (req.query.department) query = query.eq('department', req.query.department);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
}));
app.post('/maintenance', verifyToken, requireRole(HOD_UP), hotelAccess('body'), wrap(async (req, res) => {
  const hotel_id = req.body.hotel_id, next_due = req.body.next_due;
  const department = sanitize(clip(req.body.department, 40)), title = sanitize(clip(req.body.title, 150)), description = sanitize(clip(req.body.description, 1000));
  const frequency = sanitize(clip(req.body.frequency || 'daily', 30)), created_by = sanitize(clip(req.body.created_by, 60));
  if (!title) return res.status(400).json({ error: 'Title required.' });
  const { data, error } = await supabase.from('maintenance_tasks').insert([{ hotel_id, department, title, description, frequency, next_due, created_by, is_active: true }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
}));
app.post('/maintenance/:id/done', verifyToken, requireRole(HOD_UP), resourceAccess('maintenance_tasks'), wrap(async (req, res) => {
  const { last_done, next_due } = req.body;
  const { data, error } = await supabase.from('maintenance_tasks').update({ last_done, next_due }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
}));
app.delete('/maintenance/:id', verifyToken, requireRole(HOD_UP), resourceAccess('maintenance_tasks'), wrap(async (req, res) => {
  const { error } = await supabase.from('maintenance_tasks').update({ is_active: false }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
}));

// ── QR (guest scans a room QR code) — returns only what the guest page needs ──
app.get('/qr/:room_id', wrap(async (req, res) => {
  const id = parseInt(req.params.room_id);
  if (!id) return res.status(400).json({ error: 'Invalid room.' });
  const { data, error } = await supabase.from('rooms').select('id, room_number, hotel_id, floor').eq('id', id).maybeSingle();
  if (error || !data) return res.status(404).json({ error: 'Room not found.' });
  res.json(data);
}));

// ── DELETE HOTEL / ACCOUNT (owner only) ──────────────────────────────────────
const HOTEL_TABLES = ['requests', 'staff', 'hod', 'rooms', 'announcements', 'checkout_reviews', 'maintenance_tasks'];
async function wipeHotel(hotel_id) {
  for (const t of HOTEL_TABLES) await supabase.from(t).delete().eq('hotel_id', hotel_id);
  await supabase.from('hotels').delete().eq('hotel_id', hotel_id);
}
app.post('/hotels/:hotel_id/delete', verifyToken, requireRole(['owner']), noDemo, hotelAccess('params'), wrap(async (req, res) => {
  const { hotel_id } = req.params;
  for (const t of HOTEL_TABLES) await supabase.from(t).delete().eq('hotel_id', hotel_id);
  const { error } = await supabase.from('hotels').delete().eq('hotel_id', hotel_id);
  if (error) return res.status(500).json({ error: error.message });
  forgetOwner(req.user.owner_id);
  res.json({ success: true });
}));

app.post('/owner/delete', verifyToken, requireRole(['owner']), noDemo, wrap(async (req, res) => {
  const owner_id = req.user.owner_id;
  const { data: hotels } = await supabase.from('hotels').select('hotel_id').eq('owner_id', owner_id);
  for (const h of (hotels || [])) { if (h.hotel_id) await wipeHotel(h.hotel_id); }
  await supabase.from('hotels').delete().eq('owner_id', owner_id);
  await supabase.from('owners').delete().eq('id', owner_id);
  forgetOwner(owner_id);
  res.json({ success: true });
}));

app.get('/legal', (req,res) => res.send(`
<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Welco Legal</title>
<style>body{font-family:sans-serif;max-width:700px;margin:40px auto;padding:20px;color:#333}h1{color:#005f73}p{line-height:1.7}</style>
</head><body>
<h1>© 2026 Welco™</h1>
<p><strong>All Rights Reserved.</strong></p>
<p>Welco™ is a proprietary hotel management platform developed and owned by Welco Technologies, India.</p>
<p>Unauthorized copying, reproduction, modification, distribution, or use of any part of this software,
its design, code, or intellectual property is strictly prohibited without written permission from Welco Technologies.</p>
<p>Welco™ is a registered trademark. Any unauthorized use of the Welco name, logo, or brand is a violation of trademark law.</p>
<h2>Contact</h2>
<p>For licensing inquiries: welco.app</p>
<p>Built with ❤️ in India 🇮🇳</p>
</body></html>
`));

// Anything unknown under the API gets a clean JSON error instead of a stack trace
app.use(function(err, req, res, next) {
  if (res.headersSent) return next(err);
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'That upload is too large.' });
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Bad request.' });
  console.error('Unhandled error:', err && err.message ? err.message : err);
  res.status(500).json({ error: 'Server error. Please try again.' });
});

app.listen(PORT, () => console.log('Welco server running on port ' + PORT));