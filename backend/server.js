// Import dependencies
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Import models
const User = require('./models/User');
const Invoice = require('./models/Invoice');

// App setup
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'frontend', 'public', 'html')));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Auth Middleware
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).send({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).send({ error: 'Invalid token' });
  }
};

// Routes
// Serve index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/public/html/index.html'));
});

// Signup
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).send({ error: 'Email already registered' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = new User({ email, passwordHash, plan: 'free' });
    await user.save();

    res.send({ message: 'User created successfully' });
  } catch (err) {
    res.status(400).send({ error: 'Signup failed', details: err.message });
  }
});


// Login
app.post('/api/login', async (req, res) => {  
    try {  
      const { email, password } = req.body;  
  
      console.log('Login attempt:', { email }); // Log login attempt  
  
      const user = await User.findOne({ email });  
      if (!user) {  
        console.log('User not found:', email);  
        return res.status(400).send({ error: 'User not found' });  
      }  
  
      const isMatch = await bcrypt.compare(password, user.passwordHash);  
      if (!isMatch) {  
        console.log('Invalid password for:', email);  
        return res.status(400).send({ error: 'Invalid credentials' });  
      }  
  
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });  
      res.send({ token });  
    } catch (err) {  
      console.error('Login error:', err);  
      res.status(500).send({   
        error: 'Login failed',   
        details: err.message   
      });  
    }  
});  

// Generate PDF and Save Invoice
app.post('/generate-pdf', authMiddleware, async (req, res) => {
  const { yourName, yourAddress, clientName, clientAddress, services } = req.body;
  const { email } = req.body;  
  const user = await User.findOne({ _id: req.user.id });
  if (!user) {
    return res.status(404).send({ error: 'User not found' });
  }
  const doc = new PDFDocument();
  const filename = `Invoice_${Date.now()}.pdf`;
  const filePath = path.join(__dirname, 'temp', filename);
  const totalAmount = services.reduce((acc, item) => acc + (item.price * item.quantity), 0);

  // Save invoice to DB
  const invoice = new Invoice({
    userId: req.user.id,
    yourName,
    yourAddress,
    clientName,
    clientAddress,
    services,
    totalAmount
  });

  if (!fs.existsSync(path.join(__dirname, 'temp'))) {
    fs.mkdirSync(path.join(__dirname, 'temp'));
  }

  if (user.plan === 'free') {
    const invoiceCount = await Invoice.countDocuments({ userId: req.user.id });
    if (invoiceCount >= 100) {
      return res.status(403).send({
        error: 'You have reached the limit of 1 invoice. Please upgrade your plan to generate more invoices.'
      });
    }
  }

  const stream = fs.createWriteStream(filePath);
  doc.pipe(stream);

  doc.fontSize(20).text('Invoice', { align: 'center' });
  doc.moveDown();
  doc.fontSize(14).text(`From: ${yourName}`);
  doc.text(`Address: ${yourAddress}`);
  doc.moveDown();
  doc.text(`To: ${clientName}`);
  doc.text(`Address: ${clientAddress}`);
  doc.moveDown();
  doc.text('Services:');
  services.forEach(service => {
    doc.text(`- ${service.description}: ${service.price} x ${service.quantity}`);
  });

  doc.download(`Invoice_${Date.now()}.pdf`);
  doc.end();

  await invoice.save();

  stream.on('finish', () => {
    res.download(filePath, filename, (err) => {
      if (err) console.error('Download error:', err);
      fs.unlink(filePath, (err) => {
        if (err) console.error('Error deleting temp file:', err);
      });
    });
  });
});

// Fetch all invoices of logged user
app.get('/api/invoices', authMiddleware, async (req, res) => {
  const invoices = await Invoice.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json(invoices);
});

// Create checkout session (Stripe payment)
app.post('/api/create-checkout-session', authMiddleware, async (req, res) => {
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    mode: 'subscription',
    customer_email: req.body.email,
    line_items: [
      {
        price: process.env.STRIPE_PRICE_ID, // From your Stripe product
        quantity: 1,
      },
    ],
    success_url: 'https://yourwebsite.com/success?session_id={CHECKOUT_SESSION_ID}',
    cancel_url: 'https://yourwebsite.com/cancel',
  });

  res.json({ url: session.url });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Backend running at http://localhost:${PORT}`));
