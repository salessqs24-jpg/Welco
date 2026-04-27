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
const express    = require('express');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const rateLimit  = require('express-rate-limit');
const helmet     = require('helmet');
const { createClient } = require('@supabase/supabase-js');

const app      = express();
const PORT     = process.env.PORT || 3000;
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
const JWT_SECRET = process.env.JWT_SECRET || 'welco_super_secret_jwt_2026';

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 10, message: { error: 'Too many login attempts. Please wait 15 minutes.' }, validate: { xForwardedForHeader: false } });
const apiLimiter   = rateLimit({ windowMs: 60*1000,    max: 200, message: { error: 'Too many requests.' }, validate: { xForwardedForHeader: false } });

app.use('/login',        loginLimiter);
app.use('/signup',       loginLimiter);
app.use('/owner/login',  loginLimiter);
app.use('/owner/signup', loginLimiter);
app.use('/hod/verify',   loginLimiter);
app.use('/staff/verify', loginLimiter);

app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ limit: '20mb', extended: true }));

app.use(express.static(__dirname, {
  index: 'index.html',
  setHeaders: function(res, path) {
    if (path.endsWith('index.js') || path.endsWith('.env') || path.endsWith('package.json')) {
      res.status(403);
    }
  }
}));

function sanitize(str) {
  if (!str) return '';
  return String(str).replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;').trim();
}

const SALT_ROUNDS = 10;
async function hashPassword(plain) { return bcrypt.hash(plain, SALT_ROUNDS); }
async function checkPassword(plain, hashed) {
  if (!hashed) return false;
  if (!hashed.startsWith('$2')) return String(plain) === String(hashed);
  try { return await bcrypt.compare(String(plain), hashed); } catch(e) { return false; }
}
function signToken(payload) { return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' }); }

app.use(function(req, res, next) {
  var allowed = ['https://welco.onrender.com', 'http://localhost:3000', 'https://usewelco.in'];
  var origin = req.headers.origin;
  if (!origin || allowed.indexOf(origin) !== -1) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

function verifyToken(req, res, next) {
  var publicRoutes = ['/health', '/hotels', '/rooms', '/announcements', '/requests'];
  if (req.method === 'GET' && publicRoutes.some(function(r){ return req.path.startsWith(r); })) {
    return next();
  }
  var auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not authenticated. Please login again.' });
  }
  try {
    req.user = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    next();
  } catch(e) {
    return res.status(401).json({ error: 'Session expired. Please login again.' });
  }
}

function generateHotelCode(name) {
  var base = name.toUpperCase().replace(/[^A-Z]/g,'').substring(0,3);
  while (base.length < 3) base += 'X';
  return base + Math.floor(Math.random()*900+100);
}
function generateStaffId(hotelCode) { return (hotelCode||'WLC')+'-'+Math.floor(Math.random()*9000+1000); }

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

app.get('/ai/test', async (req,res) => {
  try {
    const result = await askGemini('Say exactly: Welco AI is working!');
    res.json({ success: true, response: result, key_set: !!GROQ_KEY });
  } catch(e) {
    res.json({ success: false, error: e.message, key_set: !!GROQ_KEY });
  }
});

// 1. AI GUEST CHATBOT
app.post('/ai/chat', async (req, res) => {
  const { message, hotel_name, room_number, hotel_id } = req.body;
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
app.post('/ai/upsell', async (req, res) => {
  const { hotel_name, room_number, time_of_day, recent_requests } = req.body;
  try {
    const prompt = `You are a hotel upselling AI for "${hotel_name}". Room: ${room_number}, Time: ${time_of_day || 'afternoon'}, Recent requests: ${JSON.stringify(recent_requests || [])}.
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

// 3. AI ANALYTICS
app.post('/ai/analytics', async (req, res) => {
  const { question, hotel_name, requests_summary } = req.body;
  if (!question) return res.status(400).json({ error: 'Question required' });
  try {
    const prompt = `You are a hotel analytics AI for "${hotel_name}". Data: ${JSON.stringify(requests_summary || {})}. Owner question: "${question}". Answer in 2-3 sentences, plain English, actionable.`;
    const answer = await askGemini(prompt);
    res.json({ answer });
  } catch(e) {
    res.json({ answer: 'Unable to analyze right now. Please try again.' });
  }
});

// 4. SMART ROUTING
app.post('/ai/route', async (req, res) => {
  const { message } = req.body;
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

// 5. STAFF RESPONSE SUGGESTIONS
app.post('/ai/suggest-response', async (req, res) => {
  const { request_message, department, staff_name, hotel_name } = req.body;
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
// Accepts base64 image, uploads to Supabase Storage, returns public URL
app.post('/upload', async (req, res) => {
  try {
    const { base64, filename, folder } = req.body;
    if (!base64) return res.status(400).json({ error: 'base64 required' });

    // Decode base64 — strip data URL prefix if present
    const matches = base64.match(/^data:([A-Za-z-+/]+);base64,(.+)$/);
    let buffer, contentType;
    if (matches) {
      contentType = matches[1];
      buffer = Buffer.from(matches[2], 'base64');
    } else {
      buffer = Buffer.from(base64, 'base64');
      contentType = 'image/jpeg';
    }

    const ext = contentType.includes('png') ? 'png' : 'jpg';
    const safeFolder = (folder || 'uploads').replace(/[^a-z0-9_-]/gi, '');
    const safeFile = (filename || ('img_' + Date.now())).replace(/[^a-z0-9_.-]/gi, '');
    const path = `${safeFolder}/${safeFile}.${ext}`;

    const { data, error } = await supabase.storage
      .from('welco-ids')
      .upload(path, buffer, {
        contentType,
        upsert: true
      });

    if (error) {
      console.error('Supabase storage upload error:', error.message);
      return res.status(500).json({ error: error.message });
    }

    // Get public URL
    const { data: urlData } = supabase.storage
      .from('welco-ids')
      .getPublicUrl(path);

    res.json({ success: true, url: urlData.publicUrl, path });
  } catch(e) {
    console.error('Upload error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── DEMO LOGIN ─────────────────────────────────────────────────────────────
const DEMO_HOTEL_ID = 'hotel_demo_welco';

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

app.get('/demo/login', async (req,res) => {
  try {
    const hotel = await ensureDemoHotel();
    if (!hotel) return res.status(500).json({ error: 'Demo hotel unavailable.' });
    const token = signToken({ owner_id: 'demo', email: 'demo@welco.app', is_demo: true });
    res.json({ hotel, hotels: [hotel], token, is_demo: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/demo/reset', async (req,res) => {
  try {
    await supabase.from('requests').delete().eq('hotel_id', DEMO_HOTEL_ID);
    await supabase.from('staff').delete().eq('hotel_id', DEMO_HOTEL_ID);
    await supabase.from('hod').delete().eq('hotel_id', DEMO_HOTEL_ID);
    await supabase.from('rooms').delete().eq('hotel_id', DEMO_HOTEL_ID);
    await supabase.from('hotels').delete().eq('hotel_id', DEMO_HOTEL_ID);
    const hotel = await ensureDemoHotel();
    res.json({ success: true, hotel });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// OWNER SIGNUP
app.post('/owner/signup', async (req,res) => {
  const name=sanitize(req.body.name), email=sanitize(req.body.email).toLowerCase(), password=req.body.password;
  const group_name=sanitize(req.body.group_name||''), phone=sanitize(req.body.phone||''), secret_answer=sanitize(req.body.secret_answer||'').toLowerCase();
  if (!name||!email||!password) return res.status(400).json({ error:'Name, email and password required.' });
  if (password.length<6) return res.status(400).json({ error:'Password must be at least 6 characters.' });
  const { data:existing } = await supabase.from('owners').select('id').eq('email',email).maybeSingle();
  if (existing) return res.status(400).json({ error:'Email already registered.' });
  const hashed = await hashPassword(password);
  const { data:owner, error } = await supabase.from('owners').insert([{ name,email,password:hashed,group_name,phone,secret_answer }]).select().single();
  if (error) return res.status(500).json({ error:error.message });
  res.json({ owner, token:signToken({ owner_id:owner.id, email }) });
});

// OWNER LOGIN
app.post('/owner/login', async (req,res) => {
  const emailRaw=sanitize(req.body.email), password=req.body.password;
  let { data:owner } = await supabase.from('owners').select('*').eq('email',emailRaw).maybeSingle();
  if (!owner) { const { data:o2 } = await supabase.from('owners').select('*').eq('email',emailRaw.toLowerCase()).maybeSingle(); owner=o2; }
  if (!owner) return res.status(401).json({ error:'Invalid email or password.' });
  if (!await checkPassword(password, owner.password)) return res.status(401).json({ error:'Invalid email or password.' });
  if (!owner.password.startsWith('$2')) { const h=await hashPassword(password); await supabase.from('owners').update({ password:h }).eq('id',owner.id); }
  const { data:hotels } = await supabase.from('hotels').select('*').eq('owner_id',owner.id).order('created_at',{ ascending:true });
  res.json({ owner, hotels:hotels||[], token:signToken({ owner_id:owner.id, email:owner.email }) });
});

// ADD HOTEL
app.post('/owner/add-hotel', async (req,res) => {
  const { owner_id } = req.body;
  const hotelName=sanitize(req.body.hotelName), city=sanitize(req.body.city||'');
  const roomCount=parseInt(req.body.roomCount)||0, colour=sanitize(req.body.colour||'#0a9396'), emoji=req.body.emoji||'🏨';
  if (!owner_id||!hotelName) return res.status(400).json({ error:'owner_id and hotelName required.' });
  const hotel_id='hotel_'+hotelName.toLowerCase().replace(/[^a-z0-9]/g,'').substring(0,10)+'_'+Date.now().toString().slice(-4);
  const hotel_code=generateHotelCode(hotelName);
  const { data:hotel, error } = await supabase.from('hotels').insert([{ hotel_id,name:hotelName,city,owner_id,colour,emoji,hotel_code,owner_email:'',owner_password:'' }]).select().single();
  if (error) return res.status(500).json({ error:error.message });
  if (roomCount>0) {
    const rooms=[];
    for (let i=1;i<=Math.min(roomCount,500);i++) rooms.push({ hotel_id,room_number:String(i),floor:Math.ceil(i/10),is_active:true });
    await supabase.from('rooms').insert(rooms);
  }
  res.json({ hotel });
});

// SECRET QUESTION
app.get('/owner/secret-question', async (req,res) => {
  const email=sanitize(req.query.email).toLowerCase();
  if (!email) return res.status(400).json({ error:'Email required.' });
  const { data:owner } = await supabase.from('owners').select('id,secret_answer').eq('email',email).maybeSingle();
  if (!owner) return res.status(404).json({ error:'No account found.' });
  if (!owner.secret_answer) return res.status(400).json({ error:'No security question set.' });
  res.json({ found:true, question:'mother' });
});

// RESET PASSWORD
app.post('/owner/reset-password', async (req,res) => {
  const email=sanitize(req.body.email).toLowerCase(), secret_answer=sanitize(req.body.secret_answer||'').toLowerCase(), new_password=req.body.new_password;
  if (!email||!secret_answer||!new_password) return res.status(400).json({ error:'All fields required.' });
  if (new_password.length<6) return res.status(400).json({ error:'Password must be at least 6 characters.' });
  const { data:owner } = await supabase.from('owners').select('*').eq('email',email).maybeSingle();
  if (!owner) return res.status(404).json({ error:'Account not found.' });
  if ((owner.secret_answer||'').toLowerCase().trim()!==secret_answer) return res.status(401).json({ error:'Wrong answer.' });
  await supabase.from('owners').update({ password:await hashPassword(new_password) }).eq('email',email);
  res.json({ success:true });
});

// MAIN LOGIN
app.post('/login', async (req,res) => {
  const email=sanitize(req.body.email).toLowerCase(), password=req.body.password;
  const { data:owner } = await supabase.from('owners').select('*').eq('email',email).maybeSingle();
  if (owner) {
    if (!await checkPassword(password, owner.password)) return res.status(401).json({ error:'Invalid email or password.' });
    if (!owner.password.startsWith('$2')) { const h=await hashPassword(password); await supabase.from('owners').update({ password:h }).eq('id',owner.id); }
    const { data:hotels } = await supabase.from('hotels').select('*').eq('owner_id',owner.id).order('created_at',{ ascending:true });
    const hotelList=hotels||[];
    return res.json({ owner, hotels:hotelList, hotel:hotelList[0]||null, token:signToken({ owner_id:owner.id, email }) });
  }
  const { data:hotel } = await supabase.from('hotels').select('*').eq('owner_email',email).maybeSingle();
  if (!hotel) return res.status(401).json({ error:'Invalid email or password.' });
  if (!await checkPassword(password, hotel.owner_password)) return res.status(401).json({ error:'Invalid email or password.' });
  res.json({ hotel, hotels:[hotel], token:signToken({ hotel_id:hotel.hotel_id, email }) });
});

// LEGACY SIGNUP
app.post('/signup', async (req,res) => {
  const hotelName=sanitize(req.body.hotelName), city=sanitize(req.body.city||''), ownerName=sanitize(req.body.ownerName);
  const group_name=sanitize(req.body.group_name||''), roomCount=parseInt(req.body.roomCount)||10;
  const colour=sanitize(req.body.colour||'#0a9396'), emoji=req.body.emoji||'🏨';
  const email=sanitize(req.body.email).toLowerCase(), password=req.body.password;
  if (password&&password.length<6) return res.status(400).json({ error:'Password must be at least 6 characters.' });
  const { data:existingOwner } = await supabase.from('owners').select('id').eq('email',email).maybeSingle();
  const { data:existingHotel } = await supabase.from('hotels').select('id').eq('owner_email',email).maybeSingle();
  if (existingOwner||existingHotel) return res.status(400).json({ error:'Email already exists.' });
  const hashed=await hashPassword(password);
  const { data:owner } = await supabase.from('owners').insert([{ name:ownerName,email,password:hashed,group_name }]).select().single();
  const hotel_id='hotel_'+hotelName.toLowerCase().replace(/[^a-z0-9]/g,'').substring(0,10)+'_'+Date.now().toString().slice(-4);
  const hotel_code=generateHotelCode(hotelName);
  const { data:hotel, error:hotelError } = await supabase.from('hotels').insert([{ hotel_id,name:hotelName,city,owner_name:ownerName,colour,emoji,owner_email:email,owner_password:hashed,hotel_code,owner_id:owner?owner.id:null }]).select().single();
  if (hotelError) return res.status(500).json({ error:hotelError.message });
  const roomsToInsert=[];
  for (let i=1;i<=Math.min(roomCount,500);i++) roomsToInsert.push({ hotel_id,room_number:String(i),floor:Math.ceil(i/10),is_active:true });
  await supabase.from('rooms').insert(roomsToInsert);
  res.json({ hotel:{ ...hotel,hotel_id }, owner, token:signToken({ owner_id:owner?owner.id:null, email }) });
});

// HOTELS
app.get('/hotels', async (req,res) => {
  const { data,error } = await supabase.from('hotels').select('*');
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});
app.post('/hotels/:hotel_id/dept-guest-options', verifyToken, async (req,res) => {
  const { dept_guest_options } = req.body;
  const { data,error } = await supabase.from('hotels').update({ dept_guest_options }).eq('hotel_id',req.params.hotel_id).select().single();
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});
app.post('/hotels/:hotel_id/guest-options', verifyToken, async (req,res) => {
  const { guest_options } = req.body;
  const { data,error } = await supabase.from('hotels').update({ guest_options }).eq('hotel_id',req.params.hotel_id).select().single();
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});
app.post('/hotels/:hotel_id/update', verifyToken, async (req,res) => {
  const name=sanitize(req.body.name), city=sanitize(req.body.city||''), colour=sanitize(req.body.colour||''), emoji=req.body.emoji||'', logo_url=req.body.logo_url;
  const ai_kb = req.body.ai_kb || {};
  const { data,error } = await supabase.from('hotels').update({ name,city,colour,emoji,logo_url,ai_kb }).eq('hotel_id',req.params.hotel_id).select().single();
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});

// ROOMS
app.get('/rooms', async (req,res) => {
  let query=supabase.from('rooms').select('*');
  if (req.query.hotel_id) query=query.eq('hotel_id',req.query.hotel_id);
  const { data,error } = await query;
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});
app.post('/rooms', verifyToken, async (req,res) => {
  const { hotel_id } = req.body, room_number=sanitize(req.body.room_number), floor=parseInt(req.body.floor)||1, is_active=req.body.is_active!==false;
  const { data,error } = await supabase.from('rooms').insert([{ hotel_id,room_number,floor,is_active }]).select().single();
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});
app.delete('/rooms/:id', verifyToken, async (req,res) => {
  const { error } = await supabase.from('rooms').delete().eq('id',req.params.id);
  if (error) return res.status(500).json({ error:error.message });
  res.json({ success:true });
});

// STAFF
app.get('/staff', async (req,res) => {
  let query=supabase.from('staff').select('*');
  if (req.query.hotel_id) query=query.eq('hotel_id',req.query.hotel_id);
  if (req.query.department) query=query.eq('department',req.query.department);
  const { data,error } = await query;
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});
app.post('/staff', verifyToken, async (req,res) => {
  const { hotel_id } = req.body, name=sanitize(req.body.name), pin=sanitize(req.body.pin), department=sanitize(req.body.department||'General');
  if (pin.length!==4||!/^\d{4}$/.test(pin)) return res.status(400).json({ error:'PIN must be exactly 4 digits.' });
  const { data:hotelData } = await supabase.from('hotels').select('hotel_code').eq('hotel_id',hotel_id).single();
  const staff_id=generateStaffId(hotelData?hotelData.hotel_code:'WLC');
  const { data,error } = await supabase.from('staff').insert([{ hotel_id,name,pin,department,staff_id,is_active:true }]).select().single();
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});
app.post('/staff/:id/duty', verifyToken, async (req,res) => {
  const { is_on_duty } = req.body, now=new Date().toISOString(), update={ is_on_duty };
  if (is_on_duty) update.clocked_in_at=now; else update.clocked_out_at=now;
  const { data,error } = await supabase.from('staff').update(update).eq('id',req.params.id).select().single();
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});
app.delete('/staff/:id', verifyToken, async (req,res) => {
  const { error } = await supabase.from('staff').delete().eq('id',req.params.id);
  if (error) return res.status(500).json({ error:error.message });
  res.json({ success:true });
});
app.post('/staff/verify', async (req,res) => {
  const staff_id=sanitize(req.body.staff_id||''), pin=sanitize(req.body.pin||''), hotel_id=req.body.hotel_id, name=sanitize(req.body.name||'');
  let query=supabase.from('staff').select('*').eq('pin',pin).eq('is_active',true);
  if (staff_id) query=query.eq('staff_id',staff_id); else query=query.eq('hotel_id',hotel_id).eq('name',name);
  const { data } = await query.maybeSingle();
  if (!data) return res.status(401).json({ error:'Invalid Staff ID or PIN.' });
  var token = signToken({ staff_id: data.id, hotel_id: data.hotel_id, dept: data.department });
  res.json({ success:true, staff:data, token });
});

// HOD
app.get('/hod', async (req,res) => {
  const { data,error } = await supabase.from('hod').select('*').eq('hotel_id',req.query.hotel_id);
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});
app.post('/hod', verifyToken, async (req,res) => {
  const { hotel_id } = req.body, name=sanitize(req.body.name), department=sanitize(req.body.department), pin=sanitize(req.body.pin);
  if (!hotel_id||!name||!department||!pin) return res.status(400).json({ error:'All fields required.' });
  if (pin.length!==4||!/^\d{4}$/.test(pin)) return res.status(400).json({ error:'PIN must be exactly 4 digits.' });
  const { data:existing } = await supabase.from('hod').select('id').eq('hotel_id',hotel_id).eq('department',department).eq('is_active',true).maybeSingle();
  if (existing) return res.status(400).json({ error:'HOD already exists for '+department+'. Remove first.' });
  const { data,error } = await supabase.from('hod').insert([{ hotel_id,name,department,pin,is_active:true }]).select().single();
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});
app.post('/hod/:id/permissions', verifyToken, async (req,res) => {
  const { permissions } = req.body;
  const { data,error } = await supabase.from('hod').update({ permissions }).eq('id',req.params.id).select().single();
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});
app.delete('/hod/:id', verifyToken, async (req,res) => {
  const { error } = await supabase.from('hod').delete().eq('id',req.params.id);
  if (error) return res.status(500).json({ error:error.message });
  res.json({ success:true });
});
app.post('/hod/verify', async (req,res) => {
  const hotel_code=sanitize(req.body.hotel_code||''), name=sanitize(req.body.name||''), pin=sanitize(req.body.pin||'');
  if (!hotel_code) return res.status(400).json({ error:'Hotel code required.' });
  const { data:hotel } = await supabase.from('hotels').select('*').eq('hotel_code',hotel_code.toUpperCase()).maybeSingle();
  if (!hotel) return res.status(401).json({ error:'Invalid hotel code.' });
  const { data:hod } = await supabase.from('hod').select('*').eq('hotel_id',hotel.hotel_id).eq('name',name).eq('pin',pin).eq('is_active',true).maybeSingle();
  if (!hod) return res.status(401).json({ error:'Invalid name or PIN.' });
  var token = signToken({ hod_id: hod.id, hotel_id: hotel.hotel_id, dept: hod.department });
  res.json({ success:true, hod:{ ...hod, hotel }, token });
});

// REQUESTS
app.get('/requests', async (req,res) => {
  const hotel_id = req.query.hotel_id;

  if (req.query.all === 'true') {
    let query = supabase.from('requests').select('*').order('created_at', { ascending: false });
    if (hotel_id) query = query.eq('hotel_id', hotel_id);
    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });
    return res.json(data);
  }

  var days = parseInt(req.query.days) || 7;
  if (days > 90) days = 90;
  var cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - days);
  var cutoffISO = cutoff.toISOString();

  let recentQuery = supabase.from('requests').select('*')
    .order('created_at', { ascending: false })
    .gte('created_at', cutoffISO);
  if (hotel_id) recentQuery = recentQuery.eq('hotel_id', hotel_id);

  let activeQuery = supabase.from('requests').select('*')
    .in('status', ['pending', 'in_progress'])
    .lt('created_at', cutoffISO)
    .order('created_at', { ascending: false });
  if (hotel_id) activeQuery = activeQuery.eq('hotel_id', hotel_id);

  const [recentResult, activeResult] = await Promise.all([recentQuery, activeQuery]);

  if (recentResult.error) return res.status(500).json({ error: recentResult.error.message });

  var recentData = recentResult.data || [];
  var activeData = activeResult.data || [];
  var recentIds = new Set(recentData.map(function(r){ return r.id; }));
  var extraActive = activeData.filter(function(r){ return !recentIds.has(r.id); });
  var merged = recentData.concat(extraActive);
  merged.sort(function(a,b){ return new Date(b.created_at) - new Date(a.created_at); });

  res.json(merged);
});

app.post('/requests', async (req,res) => {
  const { hotel_id } = req.body, room_number=sanitize(req.body.room_number||''), category=sanitize(req.body.category||''), message=sanitize(req.body.message||''), sla_minutes=parseInt(req.body.sla_minutes)||15;
  const { data,error } = await supabase.from('requests').insert([{ hotel_id,room_number,category,message,status:'pending',sla_minutes }]).select().single();
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});
app.post('/requests/:id/claim', verifyToken, async (req,res) => {
  const claimed_by=sanitize(req.body.claimed_by||'');
  const { data,error } = await supabase.from('requests').update({ status:'in_progress',claimed_by,claimed_at:new Date().toISOString() }).eq('id',req.params.id).select().single();
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});
app.post('/requests/:id/complete', verifyToken, async (req,res) => {
  const { data,error } = await supabase.from('requests').update({ status:'done',completed_at:new Date().toISOString() }).eq('id',req.params.id).select().single();
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});
app.post('/requests/:id/feedback', async (req,res) => {
  const rating=parseInt(req.body.rating), feedback_comments=sanitize(req.body.feedback_comments||'');
  if (rating<1||rating>5) return res.status(400).json({ error:'Rating must be 1-5.' });
  const { data,error } = await supabase.from('requests').update({ feedback_rating:rating,feedback_comments }).eq('id',req.params.id).select().single();
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});

// ── CHECKOUT FEEDBACK ────────────────────────────────────────────────────────
app.post('/checkout-feedback', async (req,res) => {
  const { hotel_id, room_number, guest_name, guest_email, rating, review } = req.body;
  if (!hotel_id || !rating || !review) return res.status(400).json({ error: 'hotel_id, rating and review required.' });
  try {
    const { data, error } = await supabase.from('checkout_reviews').insert([{
      hotel_id,
      room_number: room_number || '',
      guest_name:  guest_name  || '',
      guest_email: guest_email || '',
      rating:      parseInt(rating),
      review
    }]).select().single();
    if (error) {
      // Table may not exist yet — log it but still return success so the guest experience is not broken
      console.error('checkout_reviews insert error:', error.message);
      return res.json({ success: true, fallback: true });
    }
    res.json({ success: true, data });
  } catch(e) {
    console.error('checkout-feedback error:', e.message);
    res.json({ success: true, fallback: true });
  }
});

// GET CHECKOUT REVIEWS — for admin panel
app.get('/checkout-reviews', verifyToken, async (req,res) => {
  const hotel_id = req.query.hotel_id;
  if (!hotel_id) return res.status(400).json({ error: 'hotel_id required.' });
  try {
    const { data, error } = await supabase
      .from('checkout_reviews')
      .select('*')
      .eq('hotel_id', hotel_id)
      .order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data || []);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ANNOUNCEMENTS
app.get('/announcements', async (req,res) => {
  let query=supabase.from('announcements').select('*').order('created_at',{ ascending:false });
  if (req.query.hotel_id) query=query.eq('hotel_id',req.query.hotel_id);
  const { data,error } = await query;
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});
app.post('/announcements', verifyToken, async (req,res) => {
  const { hotel_id } = req.body, message=sanitize(req.body.message||'');
  if (!message) return res.status(400).json({ error:'Message required.' });
  await supabase.from('announcements').update({ is_active:false }).eq('hotel_id',hotel_id);
  const { data,error } = await supabase.from('announcements').insert([{ hotel_id,message,is_active:true }]).select().single();
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});
app.delete('/announcements/:id', verifyToken, async (req,res) => {
  const { error } = await supabase.from('announcements').delete().eq('id',req.params.id);
  if (error) return res.status(500).json({ error:error.message });
  res.json({ success:true });
});
app.post('/announcements/:id/toggle', verifyToken, async (req,res) => {
  const { is_active } = req.body;
  const { data,error } = await supabase.from('announcements').update({ is_active }).eq('id',req.params.id).select().single();
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});

// MAINTENANCE
app.get('/maintenance', async (req,res) => {
  let query=supabase.from('maintenance_tasks').select('*').eq('is_active',true).order('next_due',{ ascending:true });
  if (req.query.hotel_id)   query=query.eq('hotel_id',req.query.hotel_id);
  if (req.query.department) query=query.eq('department',req.query.department);
  const { data,error } = await query;
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});
app.post('/maintenance', verifyToken, async (req,res) => {
  const { hotel_id,next_due } = req.body, department=sanitize(req.body.department||''), title=sanitize(req.body.title||''), description=sanitize(req.body.description||''), frequency=sanitize(req.body.frequency||'daily'), created_by=sanitize(req.body.created_by||'');
  if (!title) return res.status(400).json({ error:'Title required.' });
  const { data,error } = await supabase.from('maintenance_tasks').insert([{ hotel_id,department,title,description,frequency,next_due,created_by,is_active:true }]).select().single();
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});
app.post('/maintenance/:id/done', verifyToken, async (req,res) => {
  const { last_done,next_due } = req.body;
  const { data,error } = await supabase.from('maintenance_tasks').update({ last_done,next_due }).eq('id',req.params.id).select().single();
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});
app.delete('/maintenance/:id', verifyToken, async (req,res) => {
  const { error } = await supabase.from('maintenance_tasks').update({ is_active:false }).eq('id',req.params.id);
  if (error) return res.status(500).json({ error:error.message });
  res.json({ success:true });
});

// QR
app.get('/qr/:room_id', async (req,res) => {
  const { data,error } = await supabase.from('rooms').select('*, hotels(*)').eq('id',req.params.room_id).single();
  if (error) return res.status(500).json({ error:error.message });
  res.json(data);
});

// HOD KB SAVE
app.post('/hotels/:hotel_id/kb', verifyToken, async (req,res) => {
  try {
    const hotel_id = req.params.hotel_id;
    const { data: hotelData } = await supabase.from('hotels').select('ai_kb').eq('hotel_id', hotel_id).single();
    const currentKb = (hotelData && hotelData.ai_kb) || {};
    const newKb = Object.assign({}, currentKb, req.body.ai_kb || {});
    const { data, error } = await supabase.from('hotels').update({ ai_kb: newKb }).eq('hotel_id', hotel_id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, hotel: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// HOTEL PHOTOS
app.post('/hotels/:hotel_id/photos', verifyToken, async (req,res) => {
  try {
    const hotel_photos = req.body.hotel_photos || [];
    const { data, error } = await supabase.from('hotels')
      .update({ hotel_photos })
      .eq('hotel_id', req.params.hotel_id)
      .select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, hotel: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// DELETE HOTEL
app.post('/hotels/:hotel_id/delete', verifyToken, async (req,res) => {
  const { hotel_id } = req.params;
  try {
    await supabase.from('requests').delete().eq('hotel_id', hotel_id);
    await supabase.from('staff').delete().eq('hotel_id', hotel_id);
    await supabase.from('hod').delete().eq('hotel_id', hotel_id);
    await supabase.from('rooms').delete().eq('hotel_id', hotel_id);
    await supabase.from('announcements').delete().eq('hotel_id', hotel_id);
    await supabase.from('checkout_reviews').delete().eq('hotel_id', hotel_id);
    const { error } = await supabase.from('hotels').delete().eq('hotel_id', hotel_id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// DELETE OWNER ACCOUNT
app.post('/owner/delete', verifyToken, async (req,res) => {
  const owner_id = req.user.owner_id;
  if (!owner_id) return res.status(400).json({ error: 'Owner not identified.' });
  try {
    const { data: hotels } = await supabase.from('hotels').select('hotel_id').eq('owner_id', owner_id);
    if (hotels && hotels.length > 0) {
      for (const h of hotels) {
        await supabase.from('requests').delete().eq('hotel_id', h.hotel_id);
        await supabase.from('staff').delete().eq('hotel_id', h.hotel_id);
        await supabase.from('hod').delete().eq('hotel_id', h.hotel_id);
        await supabase.from('rooms').delete().eq('hotel_id', h.hotel_id);
        await supabase.from('announcements').delete().eq('hotel_id', h.hotel_id);
        await supabase.from('checkout_reviews').delete().eq('hotel_id', h.hotel_id);
        await supabase.from('hotels').delete().eq('hotel_id', h.hotel_id);
      }
    }
    await supabase.from('owners').delete().eq('id', owner_id);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

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

app.listen(PORT, () => console.log('Welco server running on port '+PORT));