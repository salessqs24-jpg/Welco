require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

app.use(express.json({ limit: '5mb' }));
app.use(express.static(__dirname));

// ─────────────────────────────────────────
// AUTH — SIGNUP
// ─────────────────────────────────────────
app.post('/signup', async (req, res) => {
  const { hotelName, city, ownerName, roomCount, colour, emoji, email, password } = req.body;
  const { data: existing } = await supabase.from('hotels').select('id').eq('owner_email', email).maybeSingle();
  if (existing) return res.status(400).json({ error: 'Email already exists.' });
  const hotel_id = 'hotel_' + hotelName.toLowerCase().replace(/[^a-z0-9]/g, '').substring(0, 10) + '_' + Date.now().toString().slice(-4);
  const { data: hotel, error: hotelError } = await supabase.from('hotels')
    .insert([{ hotel_id, name: hotelName, city, owner_name: ownerName, colour: colour || '#0a9396', emoji: emoji || '🏨', owner_email: email, owner_password: password }])
    .select().single();
  if (hotelError) return res.status(500).json({ error: hotelError.message });
  const roomsToInsert = [];
  for (let i = 1; i <= roomCount; i++) {
    roomsToInsert.push({ hotel_id: String(hotel_id), room_number: String(i), floor: Math.ceil(i / 10), is_active: true });
  }
  const { error: roomsError } = await supabase.from('rooms').insert(roomsToInsert);
  if (roomsError) return res.status(500).json({ error: roomsError.message });
  res.json({ hotel: { ...hotel, hotel_id, city } });
});

// ─────────────────────────────────────────
// AUTH — LOGIN
// ─────────────────────────────────────────
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const { data: hotel } = await supabase.from('hotels').select('*').eq('owner_email', email).eq('owner_password', password).maybeSingle();
  if (!hotel) return res.status(401).json({ error: 'Invalid email or password.' });
  res.json({ hotel });
});

// ─────────────────────────────────────────
// HOTELS
// ─────────────────────────────────────────
app.get('/hotels', async (req, res) => {
  const { data, error } = await supabase.from('hotels').select('*');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/hotels/:id', async (req, res) => {
  const { data, error } = await supabase.from('hotels').select('*').eq('id', req.params.id).single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/hotels/:hotel_id/update', async (req, res) => {
  const { name, city, colour, emoji, logo_url } = req.body;
  const { data, error } = await supabase.from('hotels')
    .update({ name, city, colour, emoji, logo_url }).eq('hotel_id', req.params.hotel_id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ─────────────────────────────────────────
// ROOMS
// ─────────────────────────────────────────
app.get('/rooms', async (req, res) => {
  let query = supabase.from('rooms').select('*');
  if (req.query.hotel_id) query = query.eq('hotel_id', req.query.hotel_id);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/rooms', async (req, res) => {
  const { hotel_id, room_number, floor, is_active } = req.body;
  const { data, error } = await supabase.from('rooms')
    .insert([{ hotel_id, room_number, floor, is_active }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/rooms/:id', async (req, res) => {
  const { error } = await supabase.from('rooms').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ─────────────────────────────────────────
// STAFF
// ─────────────────────────────────────────
app.get('/staff', async (req, res) => {
  const { data, error } = await supabase.from('staff').select('*').eq('hotel_id', req.query.hotel_id);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/staff', async (req, res) => {
  const { hotel_id, name, pin } = req.body;
  const { data, error } = await supabase.from('staff')
    .insert([{ hotel_id, name, pin, is_active: true }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/staff/:id', async (req, res) => {
  const { error } = await supabase.from('staff').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.post('/staff/verify', async (req, res) => {
  const { hotel_id, name, pin } = req.body;
  const { data } = await supabase.from('staff').select('*')
    .eq('hotel_id', hotel_id).eq('name', name).eq('pin', pin).eq('is_active', true).maybeSingle();
  if (!data) return res.status(401).json({ error: 'Invalid name or PIN. Ask your hotel manager to add you.' });
  res.json({ success: true, staff: data });
});

// ─────────────────────────────────────────
// HOD
// ─────────────────────────────────────────
app.get('/hod', async (req, res) => {
  const { data, error } = await supabase.from('hod').select('*').eq('hotel_id', req.query.hotel_id);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/hod', async (req, res) => {
  const { hotel_id, name, department, pin } = req.body;
  if (!hotel_id || !name || !department || !pin) return res.status(400).json({ error: 'All fields required.' });
  const { data: existing } = await supabase.from('hod').select('id')
    .eq('hotel_id', hotel_id).eq('department', department).eq('is_active', true).maybeSingle();
  if (existing) return res.status(400).json({ error: 'An HOD already exists for ' + department + '. Remove them first.' });
  const { data, error } = await supabase.from('hod')
    .insert([{ hotel_id, name, department, pin, is_active: true }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/hod/:id', async (req, res) => {
  const { error } = await supabase.from('hod').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.post('/hod/verify', async (req, res) => {
  const { hotel_id, name, pin } = req.body;
  const { data } = await supabase.from('hod').select('*')
    .eq('hotel_id', hotel_id).eq('name', name).eq('pin', pin).eq('is_active', true).maybeSingle();
  if (!data) return res.status(401).json({ error: 'Invalid name or PIN.' });
  res.json({ success: true, hod: data });
});

// ─────────────────────────────────────────
// REQUESTS
// ─────────────────────────────────────────
app.get('/requests', async (req, res) => {
  let query = supabase.from('requests').select('*').order('created_at', { ascending: false });
  if (req.query.hotel_id) query = query.eq('hotel_id', req.query.hotel_id);
  if (req.query.room_id) query = query.eq('room_id', req.query.room_id);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/requests', async (req, res) => {
  const { hotel_id, room_number, category, message } = req.body;
  const { data, error } = await supabase.from('requests')
    .insert([{ hotel_id, room_number, category, message, status: 'pending' }])
    .select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/requests/:id/claim', async (req, res) => {
  const { claimed_by } = req.body;
  const { data, error } = await supabase.from('requests')
    .update({ status: 'in_progress', claimed_by, claimed_at: new Date().toISOString() })
    .eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/requests/:id/complete', async (req, res) => {
  const { data, error } = await supabase.from('requests')
    .update({ status: 'done', completed_at: new Date().toISOString() })
    .eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/requests/:id/feedback', async (req, res) => {
  const { rating, feedback_comments } = req.body;
  const { data, error } = await supabase.from('requests')
    .update({ feedback_rating: rating, feedback_comments })
    .eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ─────────────────────────────────────────
// ANNOUNCEMENTS
// ─────────────────────────────────────────
app.get('/announcements', async (req, res) => {
  let query = supabase.from('announcements').select('*').order('created_at', { ascending: false });
  if (req.query.hotel_id) query = query.eq('hotel_id', req.query.hotel_id);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/announcements', async (req, res) => {
  const { hotel_id, message } = req.body;
  if (!hotel_id || !message) return res.status(400).json({ error: 'hotel_id and message required.' });
  await supabase.from('announcements').update({ is_active: false }).eq('hotel_id', hotel_id);
  const { data, error } = await supabase.from('announcements')
    .insert([{ hotel_id, message, is_active: true }]).select().single();
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
  const { data, error } = await supabase.from('announcements')
    .update({ is_active }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});


// ─────────────────────────────────────────
// MAINTENANCE TASKS
// ─────────────────────────────────────────
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
  if (!hotel_id || !title || !frequency) return res.status(400).json({ error: 'hotel_id, title and frequency required.' });
  const { data, error } = await supabase.from('maintenance_tasks')
    .insert([{ hotel_id, department, title, description, frequency, next_due, created_by, is_active: true }])
    .select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/maintenance/:id/done', async (req, res) => {
  const { last_done, next_due } = req.body;
  const { data, error } = await supabase.from('maintenance_tasks')
    .update({ last_done, next_due }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/maintenance/:id', async (req, res) => {
  const { error } = await supabase.from('maintenance_tasks').update({ is_active: false }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ─────────────────────────────────────────
// QR
// ─────────────────────────────────────────
app.get('/qr/:room_id', async (req, res) => {
  const { data, error } = await supabase.from('rooms').select('*, hotels(*)').eq('id', req.params.room_id).single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ─────────────────────────────────────────
// START
// ─────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ Welco server running at http://localhost:${PORT}`);
});