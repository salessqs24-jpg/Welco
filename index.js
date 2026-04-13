require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

app.use(express.json({ limit: '5mb' }));
app.use(express.static(__dirname));

// Health check — Render pings this to confirm app is alive
app.get('/health', (req, res) => res.json({ status: 'ok', ts: Date.now() }));

function generateHotelCode(name) {
  var base = name.toUpperCase().replace(/[^A-Z]/g, '').substring(0, 3);
  while (base.length < 3) base += 'X';
  return base + Math.floor(Math.random() * 900 + 100);
}

function generateStaffId(hotelCode) {
  return (hotelCode || 'WLC') + '-' + Math.floor(Math.random() * 9000 + 1000);
}

// ── OWNER SIGNUP ──────────────────────────────────────────────────────────────
app.post('/owner/signup', async (req, res) => {
  const { name, email, password, group_name, phone, secret_answer } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password required.' });
  const { data: existing } = await supabase.from('owners').select('id').eq('email', email).maybeSingle();
  if (existing) return res.status(400).json({ error: 'Email already registered. Please login.' });
  const { data: owner, error } = await supabase.from('owners')
    .insert([{ name, email, password, group_name: group_name || '', phone: phone || '', secret_answer: (secret_answer || '').toLowerCase() }])
    .select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ owner });
});

// ── OWNER LOGIN ───────────────────────────────────────────────────────────────
app.post('/owner/login', async (req, res) => {
  const { email, password } = req.body;
  const { data: owner } = await supabase.from('owners').select('*').eq('email', email).eq('password', password).maybeSingle();
  if (!owner) return res.status(401).json({ error: 'Invalid email or password.' });
  const { data: hotels } = await supabase.from('hotels').select('*').eq('owner_id', owner.id).order('created_at', { ascending: true });
  res.json({ owner, hotels: hotels || [] });
});

// ── ADD HOTEL ─────────────────────────────────────────────────────────────────
app.post('/owner/add-hotel', async (req, res) => {
  const { owner_id, hotelName, city, roomCount, colour, emoji } = req.body;
  if (!owner_id || !hotelName) return res.status(400).json({ error: 'owner_id and hotelName required.' });
  const hotel_id = 'hotel_' + hotelName.toLowerCase().replace(/[^a-z0-9]/g, '').substring(0, 10) + '_' + Date.now().toString().slice(-4);
  const hotel_code = generateHotelCode(hotelName);
  const { data: hotel, error } = await supabase.from('hotels')
    .insert([{ hotel_id, name: hotelName, city, owner_id, colour: colour || '#0a9396', emoji: emoji || '🏨', hotel_code, owner_email: '', owner_password: '' }])
    .select().single();
  if (error) return res.status(500).json({ error: error.message });
  if (roomCount && roomCount > 0) {
    const rooms = [];
    for (let i = 1; i <= Math.min(roomCount, 500); i++) rooms.push({ hotel_id, room_number: String(i), floor: Math.ceil(i / 10), is_active: true });
    await supabase.from('rooms').insert(rooms);
  }
  res.json({ hotel });
});

// ── SECRET QUESTION ───────────────────────────────────────────────────────────
app.get('/owner/secret-question', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'Email required.' });
  const { data: owner } = await supabase.from('owners').select('id, secret_answer').eq('email', email).maybeSingle();
  if (!owner) return res.status(404).json({ error: 'No account found with this email.' });
  if (!owner.secret_answer) return res.status(400).json({ error: 'No security question set.' });
  res.json({ found: true, question: 'mother' });
});

// ── RESET PASSWORD ────────────────────────────────────────────────────────────
app.post('/owner/reset-password', async (req, res) => {
  const { email, secret_answer, new_password } = req.body;
  if (!email || !secret_answer || !new_password) return res.status(400).json({ error: 'All fields required.' });
  const { data: owner } = await supabase.from('owners').select('*').eq('email', email).maybeSingle();
  if (!owner) return res.status(404).json({ error: 'Account not found.' });
  if (!owner.secret_answer) return res.status(400).json({ error: 'No security question set.' });
  if (owner.secret_answer.toLowerCase().trim() !== secret_answer.toLowerCase().trim()) return res.status(401).json({ error: 'Wrong answer.' });
  await supabase.from('owners').update({ password: new_password }).eq('email', email);
  res.json({ success: true });
});

// ── MAIN LOGIN (tries owners first, falls back to legacy hotels table) ─────────
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const { data: owner } = await supabase.from('owners').select('*').eq('email', email).eq('password', password).maybeSingle();
  if (owner) {
    const { data: hotels } = await supabase.from('hotels').select('*').eq('owner_id', owner.id).order('created_at', { ascending: true });
    const hotelList = hotels || [];
    return res.json({ owner, hotels: hotelList, hotel: hotelList[0] || null });
  }
  const { data: hotel } = await supabase.from('hotels').select('*').eq('owner_email', email).eq('owner_password', password).maybeSingle();
  if (!hotel) return res.status(401).json({ error: 'Invalid email or password.' });
  res.json({ hotel, hotels: [hotel] });
});

// ── LEGACY SIGNUP ─────────────────────────────────────────────────────────────
app.post('/signup', async (req, res) => {
  const { hotelName, city, ownerName, roomCount, colour, emoji, email, password } = req.body;
  const { data: existingOwner } = await supabase.from('owners').select('id').eq('email', email).maybeSingle();
  const { data: existingHotel } = await supabase.from('hotels').select('id').eq('owner_email', email).maybeSingle();
  if (existingOwner || existingHotel) return res.status(400).json({ error: 'Email already exists.' });
  const { data: owner } = await supabase.from('owners').insert([{ name: ownerName, email, password, group_name: '' }]).select().single();
  const hotel_id = 'hotel_' + hotelName.toLowerCase().replace(/[^a-z0-9]/g, '').substring(0, 10) + '_' + Date.now().toString().slice(-4);
  const hotel_code = generateHotelCode(hotelName);
  const { data: hotel, error: hotelError } = await supabase.from('hotels')
    .insert([{ hotel_id, name: hotelName, city, owner_name: ownerName, colour: colour || '#0a9396', emoji: emoji || '🏨', owner_email: email, owner_password: password, hotel_code, owner_id: owner ? owner.id : null }])
    .select().single();
  if (hotelError) return res.status(500).json({ error: hotelError.message });
  const roomsToInsert = [];
  for (let i = 1; i <= roomCount; i++) roomsToInsert.push({ hotel_id, room_number: String(i), floor: Math.ceil(i / 10), is_active: true });
  await supabase.from('rooms').insert(roomsToInsert);
  res.json({ hotel: { ...hotel, hotel_id }, owner });
});

// ── HOTELS ────────────────────────────────────────────────────────────────────
app.get('/hotels', async (req, res) => {
  const { data, error } = await supabase.from('hotels').select('*');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/hotels/:hotel_id/dept-guest-options', async (req, res) => {
  const { dept_guest_options } = req.body;
  const { data, error } = await supabase.from('hotels').update({ dept_guest_options }).eq('hotel_id', req.params.hotel_id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/hotels/:hotel_id/guest-options', async (req, res) => {
  const { guest_options } = req.body;
  const { data, error } = await supabase.from('hotels').update({ guest_options }).eq('hotel_id', req.params.hotel_id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/hotels/:hotel_id/update', async (req, res) => {
  const { name, city, colour, emoji, logo_url } = req.body;
  const { data, error } = await supabase.from('hotels').update({ name, city, colour, emoji, logo_url }).eq('hotel_id', req.params.hotel_id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ── ROOMS ─────────────────────────────────────────────────────────────────────
app.get('/rooms', async (req, res) => {
  let query = supabase.from('rooms').select('*');
  if (req.query.hotel_id) query = query.eq('hotel_id', req.query.hotel_id);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/rooms', async (req, res) => {
  const { hotel_id, room_number, floor, is_active } = req.body;
  const { data, error } = await supabase.from('rooms').insert([{ hotel_id, room_number, floor, is_active }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/rooms/:id', async (req, res) => {
  const { error } = await supabase.from('rooms').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ── STAFF ─────────────────────────────────────────────────────────────────────
app.get('/staff', async (req, res) => {
  let query = supabase.from('staff').select('*');
  if (req.query.hotel_id) query = query.eq('hotel_id', req.query.hotel_id);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/staff', async (req, res) => {
  const { hotel_id, name, pin, department } = req.body;
  const { data: hotelData } = await supabase.from('hotels').select('hotel_code').eq('hotel_id', hotel_id).single();
  const staff_id = generateStaffId(hotelData ? hotelData.hotel_code : 'WLC');
  const { data, error } = await supabase.from('staff').insert([{ hotel_id, name, pin, department: department || 'General', staff_id, is_active: true }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Staff duty toggle (clock in / clock out)
app.post('/staff/:id/duty', async (req, res) => {
  const { is_on_duty } = req.body;
  const now = new Date().toISOString();
  const update = { is_on_duty };
  if (is_on_duty) update.clocked_in_at = now;
  else update.clocked_out_at = now;
  const { data, error } = await supabase.from('staff').update(update).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/staff/:id', async (req, res) => {
  const { error } = await supabase.from('staff').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.post('/staff/verify', async (req, res) => {
  const { staff_id, pin, hotel_id, name } = req.body;
  let query = supabase.from('staff').select('*').eq('pin', pin).eq('is_active', true);
  if (staff_id) query = query.eq('staff_id', staff_id);
  else query = query.eq('hotel_id', hotel_id).eq('name', name);
  const { data } = await query.maybeSingle();
  if (!data) return res.status(401).json({ error: 'Invalid Staff ID or PIN.' });
  res.json({ success: true, staff: data });
});

// ── HOD ───────────────────────────────────────────────────────────────────────
app.get('/hod', async (req, res) => {
  const { data, error } = await supabase.from('hod').select('*').eq('hotel_id', req.query.hotel_id);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/hod', async (req, res) => {
  const { hotel_id, name, department, pin } = req.body;
  if (!hotel_id || !name || !department || !pin) return res.status(400).json({ error: 'All fields required.' });
  const { data: existing } = await supabase.from('hod').select('id').eq('hotel_id', hotel_id).eq('department', department).eq('is_active', true).maybeSingle();
  if (existing) return res.status(400).json({ error: 'HOD already exists for ' + department + '. Remove first.' });
  const { data, error } = await supabase.from('hod').insert([{ hotel_id, name, department, pin, is_active: true }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Update HOD permissions
app.post('/hod/:id/permissions', async (req, res) => {
  const { permissions } = req.body;
  const { data, error } = await supabase.from('hod').update({ permissions }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/hod/:id', async (req, res) => {
  const { error } = await supabase.from('hod').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.post('/hod/verify', async (req, res) => {
  const { hotel_code, name, pin } = req.body;
  if (!hotel_code) return res.status(400).json({ error: 'Hotel code required.' });
  const { data: hotel } = await supabase.from('hotels').select('*').eq('hotel_code', hotel_code.toUpperCase()).maybeSingle();
  if (!hotel) return res.status(401).json({ error: 'Invalid hotel code.' });
  const { data: hod } = await supabase.from('hod').select('*').eq('hotel_id', hotel.hotel_id).eq('name', name).eq('pin', pin).eq('is_active', true).maybeSingle();
  if (!hod) return res.status(401).json({ error: 'Invalid name or PIN.' });
  res.json({ success: true, hod: { ...hod, hotel } });
});

// ── REQUESTS ──────────────────────────────────────────────────────────────────
app.get('/requests', async (req, res) => {
  let query = supabase.from('requests').select('*').order('created_at', { ascending: false });
  if (req.query.hotel_id) query = query.eq('hotel_id', req.query.hotel_id);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/requests', async (req, res) => {
  const { hotel_id, room_number, category, message, sla_minutes } = req.body;
  const { data, error } = await supabase.from('requests').insert([{ hotel_id, room_number, category, message, status: 'pending', sla_minutes: sla_minutes || 15 }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/requests/:id/claim', async (req, res) => {
  const { claimed_by } = req.body;
  const { data, error } = await supabase.from('requests').update({ status: 'in_progress', claimed_by, claimed_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/requests/:id/complete', async (req, res) => {
  const { data, error } = await supabase.from('requests').update({ status: 'done', completed_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/requests/:id/feedback', async (req, res) => {
  const { rating, feedback_comments } = req.body;
  const { data, error } = await supabase.from('requests').update({ feedback_rating: rating, feedback_comments }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ── ANNOUNCEMENTS ─────────────────────────────────────────────────────────────
app.get('/announcements', async (req, res) => {
  let query = supabase.from('announcements').select('*').order('created_at', { ascending: false });
  if (req.query.hotel_id) query = query.eq('hotel_id', req.query.hotel_id);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/announcements', async (req, res) => {
  const { hotel_id, message } = req.body;
  await supabase.from('announcements').update({ is_active: false }).eq('hotel_id', hotel_id);
  const { data, error } = await supabase.from('announcements').insert([{ hotel_id, message, is_active: true }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/announcements/:id', async (req, res) => {
  const { error } = await supabase.from('announcements').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.post('/announcements/:id/toggle', async (req, res) => {
  const { is_active } = req.body;
  const { data, error } = await supabase.from('announcements').update({ is_active }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ── MAINTENANCE ───────────────────────────────────────────────────────────────
app.get('/maintenance', async (req, res) => {
  let query = supabase.from('maintenance_tasks').select('*').eq('is_active', true).order('next_due', { ascending: true });
  if (req.query.hotel_id) query = query.eq('hotel_id', req.query.hotel_id);
  if (req.query.department) query = query.eq('department', req.query.department);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/maintenance', async (req, res) => {
  const { hotel_id, department, title, description, frequency, next_due, created_by } = req.body;
  const { data, error } = await supabase.from('maintenance_tasks').insert([{ hotel_id, department, title, description, frequency, next_due, created_by, is_active: true }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/maintenance/:id/done', async (req, res) => {
  const { last_done, next_due } = req.body;
  const { data, error } = await supabase.from('maintenance_tasks').update({ last_done, next_due }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/maintenance/:id', async (req, res) => {
  const { error } = await supabase.from('maintenance_tasks').update({ is_active: false }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ── QR ────────────────────────────────────────────────────────────────────────
app.get('/qr/:room_id', async (req, res) => {
  const { data, error } = await supabase.from('rooms').select('*, hotels(*)').eq('id', req.params.room_id).single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.listen(PORT, () => console.log('Welco server running on port ' + PORT));