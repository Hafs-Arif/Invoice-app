const mongoose = require('mongoose');

const invoiceSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  yourName: String,
  yourAddress: String,
  clientName: String,
  clientAddress: String,
  services: [
    {
      description: String,
      price: Number,
      quantity: Number
    }
  ],
  totalAmount: Number,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Invoice', invoiceSchema);
