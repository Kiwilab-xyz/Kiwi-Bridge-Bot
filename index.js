const { Telegraf, Markup, session } = require('telegraf');
const WalletModel = require('./walletModel');
const BridgeModel = require('./bridgeModel');
const db = require('./db');
require("dotenv").config();

const { transferToken, createWallet, importWallet, checkBalance, bridgeNativeTokens, bridgeNonNativeTokens, bridgeUSDC, redeemNativeTokens, redeemTokens, redeemUSDC } = require('./utils');

const bot = new Telegraf(process.env.TELEGRAM_BOT_TOKEN);

// Use session middleware
bot.use(session());  

// Middleware to ensure session exists
bot.use((ctx, next) => {
  if (!ctx.session) {
    ctx.session = {};
  }
  return next();
});

// Function to validate URL
function isValidUrl(string) {
  try {
    new URL(string);
    return true;
  } catch (_) {
    return false;  
  }
}


const networks = ['EVM', 'SOLANA', 'SUI', 'ALGORAND', 'APTOS'];
const withdrawNetworks = ['ETHEREUM', 'SOLANA', 'BNB', 'ARBITRUM', 'SCROLL', 'ALGORAND', 'SUI', 'APTOS', 'BASE', 'POLYGON', 'OPTIMISM'];
const balanceNetworks = ['ETHEREUM', 'SOLANA', 'BNB', 'ARBITRUM', 'SCROLL', 'ALGORAND', 'SUI', 'APTOS', 'BASE', 'POLYGON', 'OPTIMISM'];
const EVM_NETWORKS = ['ETHEREUM', 'ARBITRUM', 'SCROLL', 'BASE', 'POLYGON', 'OPTIMISM', 'BNB'];
const usdcBridgeNetworks = ['ETHEREUM', 'SOLANA', 'BASE', 'ARBITRUM'];


function createInlineKeyboard(buttons, columns = 2) {
  const keyboard = [];
  for (let i = 0; i < buttons.length; i += columns) {
    const row = buttons.slice(i, i + columns).map(button => {
      const callbackData = button.callback_data.length > 64 
        ? button.callback_data.slice(0, 60) + '...'
        : button.callback_data;
      return { ...button, callback_data: callbackData };
    });
    keyboard.push(row);
  }
  keyboard.push([Markup.button.callback('🏠 Main Menu', 'main_menu')]);
  return Markup.inlineKeyboard(keyboard);
}

bot.start(async (ctx) => {
  ctx.session = { step: 'initialStep' };
  const userId = ctx.from.id;
  const userWallet = await WalletModel.findOne({ userId });

  const welcomeMessage = `*Welcome to Kiwi Bridge Bot from Kiwi Protocol! 🥝🤖*

Kiwi Bridge Bot is an innovative Telegram chat bot that enables:
• Seamless cross-chain asset bridging 🌉
• Non-custodial multi-chain wallet management 👛
• User-friendly chat interface 💬

Leveraging the Wormhole SDK, Portal Bridge, NTT, and CCTP frameworks, Kiwi Bridge Bot facilitates instant transfers of native, non-native and USDC tokens across multiple blockchains. Earn "Kiwi Marks" through bridging and referrals! 🎁

*Testnet Version*
 
Choose an option:`;

  const keyboard = Markup.keyboard([
    ['Multi-chain Wallet 👛', 'Bridge Assets 🌉'],
    ['Kiwi Marks 🥝', 'Documentation 📚'],
    ['Refer and Earn 🎁', 'Kiwi Community 👥'],
  ]).oneTime().resize();

  await ctx.replyWithMarkdown(welcomeMessage, keyboard);
});

bot.hears('Multi-chain Wallet 👛', async (ctx) => {
  ctx.session = { step: 'multiChainWallet' };
  const userId = ctx.from.id;

  const userWallet = await WalletModel.findOne({ userId });

  const keyboard = userWallet
    ? Markup.keyboard([
        ['Create Wallet 🆕', 'Import Wallet 📥'],
        ['Deposit 💰', 'Withdraw 💸'],
        ['Change PIN 🔐', 'Check Balance 💼']
      ]).oneTime().resize()
    : Markup.keyboard([
        ['Create Wallet 🆕', 'Import Wallet 📥'],
        ['Deposit 💰', 'Withdraw 💸'],
      ]).oneTime().resize();

  const message = userWallet
    ? '*You have an existing wallet. What would you like to do?*'
    : '*You do not have an existing wallet. Create or Import Wallet.*';

  ctx.replyWithMarkdown(message, keyboard);
});

bot.hears('Create Wallet 🆕', async (ctx) => {
  ctx.session = { step: 'createWallet' };
  const buttons = networks.map(network => Markup.button.callback(network, `create_${network}`));
  const keyboard = createInlineKeyboard(buttons);
  await ctx.reply('Please select the type of wallet you want to create:', keyboard);
});

networks.forEach(network => {
  bot.action(`create_${network}`, async (ctx) => {
    await ctx.answerCbQuery();
    await createWallet(ctx, network);
  });
});

bot.hears('Import Wallet 📥', async (ctx) => {
  ctx.session = { step: 'importWallet' };
  const buttons = networks.map(network => Markup.button.callback(network, `import_${network}`));
  const keyboard = createInlineKeyboard(buttons);
  await ctx.reply('Please select the type of wallet you want to import:', keyboard);
});

networks.forEach(network => {
  bot.action(`import_${network}`, async (ctx) => {
    await ctx.answerCbQuery();
    ctx.session.importNetwork = network;
    await ctx.reply(`Please enter your private key for ${network}:`);
  });
});

bot.hears('Withdraw 💸', async (ctx) => {
  ctx.session = { step: 'withdraw' };
  const userId = ctx.from.id;
  const userWallets = await WalletModel.find({ userId });

  if (!userWallets || userWallets.length === 0) {
    await ctx.reply('No wallets found for your account. Please create or import a wallet.');
    return;
  }

  const buttons = withdrawNetworks.map(network => Markup.button.callback(network, `withdraw_${network}`));
  const keyboard = createInlineKeyboard(buttons);
  await ctx.reply('Please select the network for withdrawal:', keyboard);
});

withdrawNetworks.forEach(network => {
  bot.action(`withdraw_${network}`, async (ctx) => {
    await ctx.answerCbQuery();
    const keyboard = createInlineKeyboard([
      Markup.button.callback('Withdraw Native Tokens', `native_${network}`),
      Markup.button.callback('Withdraw Non-native Tokens', `nonnative_${network}`)
    ], 1);
    await ctx.reply(`You selected ${network}. What type of token do you want to withdraw?`, keyboard);
  });

  ['native', 'nonnative'].forEach(type => {
    bot.action(`${type}_${network}`, async (ctx) => {
      await ctx.answerCbQuery();
      ctx.session.withdrawType = { network, type };
      const userId = ctx.from.id;
      
      let userWallets;
      if (EVM_NETWORKS.includes(network)) {
        userWallets = await WalletModel.find({ userId, network: 'EVM' });
      } else {
        userWallets = await WalletModel.find({ userId, network });
      }
      
      if (userWallets.length === 0) {
        const walletType = EVM_NETWORKS.includes(network) ? 'EVM' : network;
        await ctx.reply(`You don't have any ${walletType} wallets. Would you like to create one?`,
          Markup.inlineKeyboard([
            Markup.button.callback('Create Wallet', `create_${walletType}`),
            Markup.button.callback('Go Back', 'withdraw_menu')
          ])
        );
        return;
      }

      const buttons = userWallets.map(wallet => {
        const shortAddress = `${wallet.address.slice(0, 6)}...${wallet.address.slice(-4)}`;
        return Markup.button.callback(shortAddress, `wallet_${wallet.address}`);
      });
      
      const keyboard = createInlineKeyboard(buttons, 1);
      await ctx.reply(`Please select the ${network} wallet for the transaction:`, keyboard);
    });
  });
});

bot.action(/^wallet_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const walletAddress = ctx.match[1];

  

    const wallet = await WalletModel.findOne({ 
      address: { $regex: new RegExp(`^${walletAddress}`, 'i') }
    });
    
    if (!wallet) {
      throw new Error('Wallet not found');
    }
    ctx.session.selectedWallet = wallet.address;
  
  await ctx.reply('Please enter the amount you want to withdraw:');
});

bot.action('withdraw_menu', async (ctx) => { 
  await ctx.answerCbQuery();
  delete ctx.session.withdrawType;
  
  const buttons = withdrawNetworks.map(network => Markup.button.callback(network, `withdraw_${network}`));
  const keyboard = createInlineKeyboard(buttons);
  await ctx.reply('Please select the network for withdrawal:', keyboard);
});
// ... (previous code remains the same)

bot.hears('Check Balance 💼', async (ctx) => {
  ctx.session.step = 'checkBalance';
  const buttons = balanceNetworks.map(network => Markup.button.callback(network, `balance_${network}`));
  const keyboard = createInlineKeyboard(buttons);
  await ctx.reply('Please select the network to check balance:', keyboard);
});

balanceNetworks.forEach(network => {
  bot.action(`balance_${network}`, async (ctx) => {
    await ctx.answerCbQuery();
    const userId = ctx.from.id;
    
    let userWallets;
    if (EVM_NETWORKS.includes(network)) {
      userWallets = await WalletModel.find({ userId, network: 'EVM' });
    } else {
      userWallets = await WalletModel.find({ userId, network });
    }
    
    if (userWallets.length === 0) {
      const walletType = EVM_NETWORKS.includes(network) ? 'EVM' : network;
      await ctx.reply(`You don't have any ${walletType} wallets. Would you like to create one?`,
        Markup.inlineKeyboard([
          Markup.button.callback('Create Wallet', `create_${network}`),
          Markup.button.callback('Go Back', 'check_balance_menu')
        ])
      );
      return;
    }

    const buttons = userWallets.map(wallet => {
      const shortAddress = `${wallet.address.slice(0, 6)}...${wallet.address.slice(-4)}`;
      return Markup.button.callback(shortAddress, `check_balance_${network}_${wallet.address}`);
    });
    
    const keyboard = createInlineKeyboard(buttons, 1);
    await ctx.reply(`Please select the ${network} wallet to check balance:`, keyboard);
  });
});

bot.action(/^check_balance_(.+)_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const network = ctx.match[1];
  const partialAddress = ctx.match[2];
  const userId = ctx.from.id;

  try {
    let fullWalletAddress;
    if (EVM_NETWORKS.includes(network)) {
      const wallet = await WalletModel.findOne({ 
        userId, 
        address: { $regex: new RegExp(`^${partialAddress}`, 'i') }
      });
      
      if (!wallet) {
        throw new Error('Wallet not found');
      }
      fullWalletAddress = wallet.address;
    } else {
      const wallet = await WalletModel.findOne({ 
        userId, 
        network, 
        address: { $regex: new RegExp(`^${partialAddress}`, 'i') }
      });
      
      if (!wallet) {
        throw new Error('Wallet not found');
      }
      fullWalletAddress = wallet.address;
    }
    
    const balance = await checkBalance(ctx, userId, network, fullWalletAddress);
    await ctx.reply(`Balance for ${network} wallet (${fullWalletAddress.slice(0, 6)}...${fullWalletAddress.slice(-4)}):\n${balance}`);
  } catch (error) {
    console.error('Error checking balance:', error);
    await ctx.reply('An error occurred while checking the balance. Please try again.');
  }
});
bot.action('check_balance_menu', async (ctx) => {
  await ctx.answerCbQuery();
  const buttons = balanceNetworks.map(network => Markup.button.callback(network, `balance_${network}`));
  const keyboard = createInlineKeyboard(buttons);
  await ctx.editMessageText('Please select the network to check balance:', keyboard);
});

// ... (rest of the code remains the same)
const bridgeNetworks = ['ETHEREUM', 'SOLANA', 'BNB', 'ARBITRUM', 'SCROLL', 'ALGORAND', 'SUI', 'APTOS', 'BASE', 'POLYGON', 'OPTIMISM'];

bot.hears('Bridge Assets 🌉', async (ctx) => {
  ctx.session = { step: 'bridgeTokens' };
  const keyboard = Markup.inlineKeyboard([
    [Markup.button.callback('Native Tokens Bridge', 'native_bridge')],
    [Markup.button.callback('Non Native Tokens Bridge', 'non_native_bridge')],
    [Markup.button.callback('Native USDC Bridge', 'usdc_bridge')],
    [Markup.button.callback('Redeem Tokens', 'redeem_tokens')]
  ]);
  await ctx.reply('Please select the type of bridge:', keyboard);  
});

bot.action('redeem_tokens', async (ctx) => {
  await ctx.answerCbQuery();
  const userId = ctx.from.id;
  
  try {
    const transactions = await BridgeModel.find({ userId });
    
    if (transactions.length === 0) {
      await ctx.reply('You have no pending bridge transactions.');
      return;
    }
    
    for (const tx of transactions) {
      const message = `
*Bridge Transaction*
Sending Network: ${tx.sendingNetwork}
Receiving Network: ${tx.receivingNetwork}
Amount: ${tx.amount}
Status: ${tx.bridgeStatus}
Type: ${tx.bridgeType}
Timestamp: ${tx.timestamp.toLocaleString()}
      `;
      
      const buttons = [];
      if (tx.bridgeStatus === 'NOT REDEEMED') {
        buttons.push(Markup.button.callback('Redeem', `redeem_${tx._id}`));
      }
      // Check if scanUrl is valid before adding the Track button
      if (tx.scanUrl && isValidUrl(tx.scanUrl)) {
        // Remove any surrounding quotes from the scanUrl
        const cleanUrl = tx.scanUrl.replace(/^["'](.+(?=["']$))["']$/, '$1');
        buttons.push(Markup.button.url('Track', cleanUrl));
      }
      
      const keyboard = Markup.inlineKeyboard(buttons);
      await ctx.replyWithMarkdown(message, keyboard);
    }
  } catch (error) {
    console.error('Error fetching bridge transactions:', error);
    await ctx.reply('An error occurred while fetching your bridge transactions. Please try again later.');
  }
});

bot.action(/^redeem_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const txId = ctx.match[1];
  
  try {
    const tx = await BridgeModel.findById(txId);
    if (!tx) {
      await ctx.reply('Transaction not found.');
      return;
    }
    
    let result;
    switch (tx.bridgeType) {
      case 'NON-NATIVE':
        result = await redeemTokens(ctx, tx.receipt, tx.sendingNetwork, tx.receivingNetwork, tx.receivingAddress, tx.sendingAddress);
        break;
      case 'NATIVE':
        result = await redeemNativeTokens(ctx, tx.receipt, tx.sendingNetwork, tx.receivingNetwork, tx.receivingAddress, tx.sendingAddress);
        break;
      case 'USDC':
        result = await redeemUSDC(ctx, tx.receipt, tx.sendingNetwork, tx.receivingNetwork, tx.receivingAddress, tx.sendingAddress);
        break;
      default:
        await ctx.reply('Unknown bridge type.');
        return;
    }
    
    if (result) {
      tx.bridgeStatus = 'REDEEMED';
      await tx.save();
      await ctx.reply('Tokens successfully redeemed!');
    } else {
      await ctx.reply('Failed to redeem tokens. Please try again later.');
    }
  } catch (error) {
    console.error('Error redeeming tokens:', error);
    await ctx.reply('An error occurred while redeeming tokens. Please try again later.');
  }
});


bot.action(['native_bridge', 'non_native_bridge', 'usdc_bridge'], async (ctx) => {
  await ctx.answerCbQuery();
  ctx.session.bridgeType = ctx.match[0];
  const networks = ctx.session.bridgeType === 'usdc_bridge' ? usdcBridgeNetworks : bridgeNetworks;
  const buttons = networks.map(network => Markup.button.callback(network, `send_from_${network}`));
  const keyboard = createInlineKeyboard(buttons);
  await ctx.editMessageText('Please select the sending network:', keyboard);
});

bot.action(/^send_from_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const sendingNetwork = ctx.match[1];
  ctx.session.sendingNetwork = sendingNetwork;
  const userId = ctx.from.id;

  let userWallets;
  if (EVM_NETWORKS.includes(sendingNetwork)) {
    userWallets = await WalletModel.find({ userId, network: 'EVM' });
  } else {
    userWallets = await WalletModel.find({ userId, network: sendingNetwork });
  }

  if (userWallets.length === 0) {
    await ctx.reply(`You don't have any ${sendingNetwork} wallets. Please create one first.`);
    return;
  }

  const buttons = userWallets.map(wallet => {
    const shortAddress = `${wallet.address.slice(0, 6)}...${wallet.address.slice(-4)}`;
    return Markup.button.callback(shortAddress, `sfa_${wallet.address}`);
  });

  const keyboard = createInlineKeyboard(buttons);
  await ctx.editMessageText('Please select the sending address:', keyboard);
});

bot.action(/^sfa_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const fullAddress = ctx.match[1];
  
  ctx.session.sendingAddress = fullAddress;

  if (ctx.session.bridgeType === 'non_native_bridge') {
    await ctx.reply('Please enter the token address:');
    ctx.session.step = 'enterTokenAddress';
  } else {
    await selectReceivingNetwork(ctx);
  }
});

async function selectReceivingNetwork(ctx) {
  const buttons = bridgeNetworks.map(network => Markup.button.callback(network, `receive_to_${network}`));
  const keyboard = createInlineKeyboard(buttons);
  await ctx.reply('Please select the receiving network:', keyboard);
}
bot.action(/^receive_to_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const receivingNetwork = ctx.match[1];
  ctx.session.receivingNetwork = receivingNetwork;
  const userId = ctx.from.id;

  let userWallets;
  if (EVM_NETWORKS.includes(receivingNetwork)) {
    userWallets = await WalletModel.find({ userId, network: 'EVM' });
  } else {
    userWallets = await WalletModel.find({ userId, network: receivingNetwork });
  }

  if (userWallets.length === 0) {
    await ctx.reply(`You don't have any ${receivingNetwork} wallets. Please create one first.`);
    return;
  }

  const buttons = userWallets.map(wallet => {
    const shortAddress = `${wallet.address.slice(0, 6)}...${wallet.address.slice(-4)}`;
    return Markup.button.callback(shortAddress, `rta_${wallet.address}`);
  });

  const keyboard = createInlineKeyboard(buttons);
  await ctx.editMessageText('Please select the receiving address:', keyboard);
});

bot.action(/^rta_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  ctx.session.receivingAddress = ctx.match[1];
  await ctx.reply('Please enter the amount of tokens to bridge:');
  ctx.session.step = 'enterAmount';
});

bot.on('text', async (ctx) => {
  console.log('Current session state:', ctx.session);

  if (ctx.session.importNetwork) {
    const privateKey = ctx.message.text;
    const network = ctx.session.importNetwork;
    await importWallet(ctx, privateKey, network);
    delete ctx.session.importNetwork;
  } else if (ctx.session.withdrawType) {
    if (!ctx.session.withdrawAmount) {
      ctx.session.withdrawAmount = ctx.message.text;
      await ctx.reply('Please enter the recipient address:');
    } else if (!ctx.session.recipientAddress) {
      ctx.session.recipientAddress = ctx.message.text;
      const { network, type } = ctx.session.withdrawType;
      const amount = ctx.session.withdrawAmount;
      const recipientAddress = ctx.session.recipientAddress;
      const walletAddress = ctx.session.selectedWallet;

      console.log('Transfer details:', { network, type, amount, recipientAddress, walletAddress });

      if (type === 'native') {
        if (!walletAddress) {
          await ctx.reply('Error: No wallet selected. Please start the withdrawal process again.');
          clearWithdrawSession(ctx);
          return;
        }

        await transferToken(ctx, network, 'native', null, amount, recipientAddress, walletAddress);
        clearWithdrawSession(ctx);
      } else if (type === 'nonnative') {
        await ctx.reply('Please enter the token address:');
      }
    } else {
      const { network, type } = ctx.session.withdrawType;
      const amount = ctx.session.withdrawAmount;
      const recipientAddress = ctx.session.recipientAddress;
      const tokenAddress = ctx.message.text;
      const walletAddress = ctx.session.selectedWallet;

      console.log('Transfer details (non-native):', { network, type, amount, recipientAddress, tokenAddress, walletAddress });

      if (!walletAddress) {
        await ctx.reply('Error: No wallet selected. Please start the withdrawal process again.');
        clearWithdrawSession(ctx);
        return;
      }

      await transferToken(ctx, network, 'nonnative', tokenAddress, amount, recipientAddress, walletAddress);
      clearWithdrawSession(ctx);
    }
  } else if (ctx.session.step === 'enterTokenAddress') {
    ctx.session.tokenAddress = ctx.message.text;
    await selectReceivingNetwork(ctx);
  } else if (ctx.session.step === 'enterAmount') {
    ctx.session.amount = ctx.message.text;
    
    const {
      bridgeType,
      sendingNetwork,
      sendingAddress,
      tokenAddress,
      receivingNetwork,
      receivingAddress,
      amount
    } = ctx.session;

    try {
      if (bridgeType === 'native_bridge') {
        await bridgeNativeTokens(ctx, sendingNetwork, sendingAddress, receivingNetwork, receivingAddress, amount);
      } else if (bridgeType === 'non_native_bridge') {
        await bridgeNonNativeTokens(ctx, sendingNetwork, sendingAddress, tokenAddress, receivingNetwork, receivingAddress, amount);
      } else if (bridgeType === 'usdc_bridge') {
        await bridgeUSDC(ctx, sendingNetwork, sendingAddress, receivingNetwork, receivingAddress, amount);
      }
    } catch (error) {
      console.error('Error during bridging:', error);
      await ctx.reply('An error occurred during the bridging process. Please try again.');
    }

    // Clear the session
    ctx.session = {};
  }
});

function clearWithdrawSession(ctx) {
  delete ctx.session.withdrawType;
  delete ctx.session.selectedWallet;
  delete ctx.session.withdrawAmount;
  delete ctx.session.recipientAddress;
}

bot.action('main_menu', async (ctx) => {
  await ctx.answerCbQuery();
  ctx.session = { step: 'initialStep' };
  const keyboard = Markup.keyboard([
    ['Multi-chain Wallet 👛', 'Bridge Assets 🌉'],
    ['Kiwi Marks 🥝', 'Documentation 📚'],
    ['Refer and Earn 🎁', 'Kiwi Community 👥'],
  ]).oneTime().resize();

  await ctx.reply('Welcome back to the main menu. Choose an option:', keyboard);
});



// Error handling
bot.catch((err, ctx) => {
  console.error(`Error for ${ctx.updateType}`, err);
  ctx.reply('An error occurred. Please try again later.');
});

bot.launch();

// Enable graceful stop
process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));