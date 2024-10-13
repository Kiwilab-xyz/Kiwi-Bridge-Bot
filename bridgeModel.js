const mongoose = require('mongoose');

const bridgeSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true,
  },
  sendingNetwork: {
    type: String,
    required: true,
  },
  sendingAddress: {
    type: String,
    required: true,
  },
  receivingNetwork: {
    type: String,
    required: true,
  },
  receivingAddress: {
    type: String,
    required: true,
  },
  amount: {
    type: String,
    required: true,
  },
  bridgeStatus: {
    type: String,
    enum: ['NOT REDEEMED', 'REDEEMED'],
    default: 'NOT REDEEMED',
  },
  bridgeType: {
    type: String,
    enum: ['NATIVE', 'NON-NATIVE', 'USDC'],
    required: true,
  },
  receipt: {
    type: mongoose.Schema.Types.Mixed,
    required: true,
  },
  scanUrl: {
    type: String,
    required: true,
  },
  timestamp: {
    type: Date,
    default: Date.now,
  }
});

const BridgeModel = mongoose.model('Bridge Tx', bridgeSchema);

module.exports = BridgeModel;
