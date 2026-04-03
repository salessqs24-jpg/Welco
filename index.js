const QRCode = require('qrcode')
const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

app.get('/', (req, res) => {
  res.json({ message: 'Welcome to Welco API!' });
});

app.get('/test-db', async (req, res) => {
  const { data, error } = await supabase.from('rooms').select('*');
  if (error) return res.json({ error: error.message });
  res.json({ data });
});
// Submit a guest request
app.post('/requests', async (req, res) => {
  const { hotel_id, room_number, category, message } = req.body;
  const { data, error } = await supabase
    .from('requests')
    .insert([{ hotel_id, room_number, category, message, status: 'pending' }])
    .select();
  if (error) return res.json({ error: error.message });
  res.json({ success: true, request: data[0] });
});

// Get all requests (for staff dashboard)
app.get('/requests', async (req, res) => {
  const { data, error } = await supabase
    .from('requests')
    .select('*')
    .order('created_at', { ascending: false });
  if (error) return res.json({ error: error.message });
  res.json({ data });
});
// Update request status (staff marks as done)
app.patch('/requests/:id', async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const { data, error } = await supabase
    .from('requests')
    .update({ status })
    .eq('id', id)
    .select();
  if (error) return res.json({ error: error.message });
  res.json({ success: true, request: data[0] });
});
// Generate QR code for a room
app.get('/qr/:hotel_id/:room_number', async (req, res) => {
  const { hotel_id, room_number } = req.params;
  const url = `http://localhost:3000/guest.html?hotel=${hotel_id}&room=${room_number}`;
  const qr = await QRCode.toDataURL(url);
  res.send(`
    <html><body style="text-align:center;font-family:sans-serif;padding:40px">
      <h2>Room ${room_number} QR Code</h2>
      <p>Hotel: ${hotel_id}</p>
      <img src="${qr}" style="width:250px"/>
      <p style="color:#888;font-size:13px">Scan to open guest portal</p>
    </body></html>
  `);
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Welco server running on port ${PORT}`);
});