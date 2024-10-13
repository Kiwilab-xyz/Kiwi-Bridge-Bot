const mongoose = require('mongoose');

const walletSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true
  },
  address: {
    type: String,
    required: true
  },
  privateKey: {
    type: String,
    required: true
  },
  network: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const WalletModel = mongoose.model('Kiwi Bridge Wallet', walletSchema);

module.exports = WalletModel;