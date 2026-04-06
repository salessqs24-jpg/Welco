require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Supabase client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// Middleware
app.use(express.json());
app.use(express.static(__dirname)); // serves index.html, guest.html, staff.html, etc.

// ─────────────────────────────────────────
// HOTELS
// ─────────────────────────────────────────

// Get all hotels
app.get('/hotels', async (req, res) => {
  const { data, error } = await supabase.from('hotels').select('*');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Get single hotel by id
app.get('/hotels/:id', async (req, res) => {
  const { data, error } = await supabase
    .from('hotels')
    .select('*')
    .eq('id', req.params.id)
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ─────────────────────────────────────────
// ROOMS
// ─────────────────────────────────────────

// Get all rooms (optionally filter by hotel)
app.get('/rooms', async (req, res) => {
  let query = supabase.from('rooms').select('*');
  if (req.query.hotel_id) query = query.eq('hotel_id', req.query.hotel_id);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ─────────────────────────────────────────
// REQUESTS
// ─────────────────────────────────────────

// Get all requests (optionally filter by hotel or room)
app.get('/requests', async (req, res) => {
  let query = supabase.from('requests').select('*').order('created_at', { ascending: false });
  if (req.query.hotel_id) query = query.eq('hotel_id', req.query.hotel_id);
  if (req.query.room_id)  query = query.eq('room_id', req.query.room_id);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Create a new request (guest submits)
app.post('/requests', async (req, res) => {
  const { room_id, hotel_id, type, note } = req.body;
  const { data, error } = await supabase
    .from('requests')
    .insert([{ room_id, hotel_id, type, note, status: 'pending' }])
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Claim a request (staff picks it up)
app.post('/requests/:id/claim', async (req, res) => {
  const { staff_name } = req.body;
  const { data, error } = await supabase
    .from('requests')
    .update({ status: 'in_progress', staff_name, claimed_at: new Date().toISOString() })
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Complete a request
app.post('/requests/:id/complete', async (req, res) => {
  const { data, error } = await supabase
    .from('requests')
    .update({ status: 'completed', completed_at: new Date().toISOString() })
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Submit feedback for a request
app.post('/requests/:id/feedback', async (req, res) => {
  const { rating, comment } = req.body;
  const { data, error } = await supabase
    .from('requests')
    .update({ rating, feedback_comment: comment })
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ─────────────────────────────────────────
// QR CODES
// ─────────────────────────────────────────

// Get QR data for a room
app.get('/qr/:room_id', async (req, res) => {
  const { data, error } = await supabase
    .from('rooms')
    .select('*, hotels(*)')
    .eq('id', req.params.room_id)
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ─────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`✅ Welco server running at http://localhost:${PORT}`);
});