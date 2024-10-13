const { ethers } = require('ethers');
const { Connection, Keypair, SystemProgram, sendAndConfirmTransaction, Transaction, PublicKey, LAMPORTS_PER_SOL } = require('@solana/web3.js');
const algosdk = require('algosdk');
const { getFullnodeUrl, SuiClient } = require('@mysten/sui/client');
const bs58 = require('bs58');
const axios = require('axios');

const { Ed25519Keypair } = require('@mysten/sui/keypairs/ed25519');
const { AptosClient, AptosAccount, CoinClient, FaucetClient } = require('aptos');
const WalletModel = require('./walletModel');
const BridgeModel = require('./bridgeModel');
const EVM_NETWORKS = ['ETHEREUM', 'ARBITRUM', 'SCROLL', 'BASE', 'POLYGON', 'OPTIMISM', 'BNB'];

const {
  attestFromAptos,
  transferFromAptos,
  redeemOnAptos,
  attestFromAlgorand,
  attestFromSui,
  transferFromAlgorand,
  transferFromSui,
  redeemOnAlgorand,
  redeemOnSui,
  transferFromEth,
  transferFromEthNative,
  attestFromEth,
  redeemOnEth,
  redeemOnEthNative,
  transferFromSolana,
  transferNativeSol,
  attestFromSolana,
  redeemOnSolana,
  redeemAndUnwrapOnSolana,
  getSignedVAA,
  getEmitterAddressAlgorand,
  getEmitterAddressEth,
  getEmitterAddressSolana,
  postVaaSolana,
  parseSequenceFromLogSolana,
  parseSequenceFromLogEth,
  parseSequenceFromLogAptos,
  parseSequenceFromLogAlgorand,
  approveEth,
  APTOS_TOKEN_BRIDGE_EMITTER_ADDRESS,
  tryNativeToUint8Array,
  CHAIN_ID_ETH,
  CHAIN_ID_SOLANA,
  CHAIN_ID_ALGORAND,
  CHAIN_ID_SUI,
  CHAIN_ID_APTOS,
  CHAIN_ID_BSC, 
  CHAIN_ID_SCROLL,
  CHAIN_ID_ARBITRUM,
  CHAIN_ID_BASE,
  CHAIN_ID_POLYGON,
  CHAIN_ID_OPTIMISM,
  CHAIN_ID_SEPOLIA,
  CHAIN_ID_ARBITRUM_SEPOLIA,
  CHAIN_ID_BASE_SEPOLIA,
  CHAIN_ID_OPTIMISM_SEPOLIA,
  CHAIN_ID_POLYGON_SEPOLIA,

  
} = require('@certusone/wormhole-sdk');

const { bech32 } = require('bech32');
const { getEmitterAddressAndSequenceFromResponseSui } = require('@certusone/wormhole-sdk/lib/cjs/sui');




const SUI_PRIVATE_KEY_PREFIX = 'suiprivkey';
const PRIVATE_KEY_SIZE = 32;
const SIGNATURE_FLAG_TO_SCHEME = {
  0: 'ED25519',
};


async function createWallet(ctx, network) {
  const userId = ctx.from.id;
  let wallet, address, privateKey;

  try {
    switch (network) {
      case 'EVM':
        wallet = ethers.Wallet.createRandom();
        address = wallet.address;
        privateKey = wallet.privateKey;
        break;
      case 'SOLANA':
        wallet = Keypair.generate();
        address = wallet.publicKey.toString();
        privateKey = Buffer.from(wallet.secretKey).toString('hex');
        break;
      case 'ALGORAND':
        wallet = algosdk.generateAccount();
        address = wallet.addr;
        privateKey = algosdk.secretKeyToMnemonic(wallet.sk);
        break;
      case 'SUI':
        wallet = Ed25519Keypair.generate();
        address = wallet.getPublicKey().toSuiAddress();
        privateKey = Buffer.from(wallet.getSecretKey()).toString('hex');
        break;
      case 'APTOS':
        wallet = new AptosAccount();
        address = wallet.address().hex();
        privateKey = Buffer.from(wallet.signingKey.secretKey).toString('hex');
        break;
      default:
        ctx.reply('Unsupported network.');
        return;
    }

    const newWallet = new WalletModel({
      userId,
      address,
      privateKey,
      network,
    });

    await newWallet.save();
    ctx.reply(`New wallet created for ${network}.\nAddress: ${address}\nPrivate Key: ${privateKey}\n\nStore your private key offline, and delete this message.`);
  } catch (error) {
    console.error(error);
    ctx.reply('An error occurred while creating the wallet. Please try again.');
  }
}

async function importWallet(ctx, privateKey, network) {
  const userId = ctx.from.id;
  let wallet, address;

  try {
    switch (network) {
      case 'EVM':
        wallet = new ethers.Wallet(privateKey);
        address = wallet.address;
        break;
      case 'SOLANA':
        wallet = Keypair.fromSecretKey(Buffer.from(privateKey, 'hex'));
        address = wallet.publicKey.toString();
        break;
      case 'ALGORAND':
        const account = algosdk.mnemonicToSecretKey(privateKey);
        wallet = account;
        address = account.addr;
        
        break;
      case 'SUI':
        const decodedKey = decodeSuiPrivateKey(privateKey);
        const { schema, secretKey } = decodedKey;
    
        if (secretKey.length !== PRIVATE_KEY_SIZE) {
          throw new Error('Wrong secretKey size. Expected 32 bytes.');
        }
    
         wallet = Ed25519Keypair.fromSecretKey(secretKey);
         address = wallet.getPublicKey().toSuiAddress(); 
    
        break;
      case 'APTOS':
        wallet = new AptosAccount(Buffer.from(privateKey, 'hex'));
        address = wallet.address().hex();
        break;
      default:
        ctx.reply('Unsupported network.');
        return;
    }

    const existingWallet = await WalletModel.findOne({ address, network });
    if (existingWallet) {
      ctx.reply('Wallet already exists.');
      return;
    }

    const newWallet = new WalletModel({
      userId,
      address,
      privateKey,
      network,
    });

    await newWallet.save();
    ctx.reply(`Wallet imported for ${network}.\nAddress: ${address}`);
  } catch (error) {
    console.error(error);
    ctx.reply('An error occurred while importing the wallet. Please check your private key and try again.');
  }
} 
 
async function transferToken(ctx, network, tokenType, tokenAddress, amount, recipientAddress, walletAddress) {

  ctx.reply(`Network:${network}, Type:${tokenType}, Token:${tokenAddress}, Amount:${amount}, Recipient:${recipientAddress}, Wallet:${walletAddress}`)
  console.log(walletAddress);
 
  try {
    const userId = ctx.from.id; 

    console.log('Transfer token params:', { network, tokenType, tokenAddress, amount, recipientAddress, walletAddress }); // Debug log

    
     // Query for the wallet
     let wallet;
     if (['ETHEREUM', 'ARBITRUM', 'SCROLL', 'BASE', 'POLYGON', 'OPTIMISM', 'BNB'].includes(network)) {
       wallet = await WalletModel.findOne({ userId, $or: [{ network: 'EVM' }, { network }], address: walletAddress });
     } 
      
     else {
       wallet = await WalletModel.findOne({ userId, network, address: walletAddress });
     }
 
     if (!wallet) {
       console.log('Wallet not found:', { userId, network, walletAddress }); // Debug log
       ctx.reply(`No ${network} wallet found for your account with the address ${walletAddress}. Please check the address and try again.`);
       return;
     }
 
     console.log('Found wallet:', wallet); // Debug log
 
    switch (network) {
      case 'ETHEREUM':
      case 'ARBITRUM':
      case 'SCROLL':
      case 'BASE':
      case 'POLYGON':
      case 'OPTIMISM':
      case 'BNB':
        await transferEVM(ctx, wallet, network, tokenType, tokenAddress, amount, recipientAddress);
        break;
      case 'SOLANA':
        await transferSolana(ctx, wallet, tokenType, tokenAddress, amount, recipientAddress);
        break;
      case 'ALGORAND':
        await transferAlgorand(ctx, wallet, tokenType, tokenAddress, amount, recipientAddress);
        break;
      case 'SUI':
        await transferSui(ctx, wallet, tokenType, tokenAddress, amount, recipientAddress);
        break;
      case 'APTOS':
        await transferAptos(ctx, wallet, tokenType, tokenAddress, amount, recipientAddress);
        break;
      default:
        ctx.reply('Unsupported network.');
        return;
    }
  } catch (error) {
    console.error('Error in transferToken:', error);
    ctx.reply('An error occurred while transferring tokens. Please try again.');
  }
}
async function transferEVM(ctx, wallet, network, tokenType, tokenAddress, amount, recipientAddress) {
  try {
    const provider = new ethers.providers.JsonRpcProvider(getProviderUrl(network));
    const signer = new ethers.Wallet(wallet.privateKey, provider);

    if (tokenType === 'native') {
      const tx = await signer.sendTransaction({
        to: recipientAddress,
        value: ethers.utils.parseEther(amount),
      });
      await tx.wait();
      ctx.reply(`Successfully transferred ${amount} native tokens to ${recipientAddress} on ${network}. Transaction hash: ${tx.hash}`);
    } else {
      const erc20Abi = ['function transfer(address to, uint256 amount) returns (bool)'];
      const contract = new ethers.Contract(tokenAddress, erc20Abi, signer);
      const tx = await contract.transfer(recipientAddress, ethers.utils.parseUnits(amount, 18));
      await tx.wait();
      ctx.reply(`Successfully transferred ${amount} tokens to ${recipientAddress} on ${network}. Transaction hash: ${tx.hash}`);
    }
  } catch (error) {
    console.error('Error in transferEVM:', error);
    ctx.reply(`Failed to transfer tokens on ${network}: ${error.message}`);
  }
}

async function transferSolana(ctx, wallet, tokenType, tokenAddress, amount, recipientAddress) {
  try {
    const connection = new Connection(getProviderUrl('SOLANA'));
    const senderKeypair = Keypair.fromSecretKey(Buffer.from(wallet.privateKey, 'hex'));
    const recipient = new PublicKey(recipientAddress);

    if (tokenType === 'native') {
      const transaction = new Transaction().add(
        SystemProgram.transfer({
          fromPubkey: senderKeypair.publicKey,
          toPubkey: recipient,
          lamports: LAMPORTS_PER_SOL * parseFloat(amount),
        })
      );
      const signature = await sendAndConfirmTransaction(connection, transaction, [senderKeypair]);
      ctx.reply(`Successfully transferred ${amount} SOL to ${recipientAddress}. Signature: ${signature}`);
    } else {
      const splToken = await import('@solana/spl-token');
      const tokenPublicKey = new PublicKey(tokenAddress);
      const fromTokenAccount = await splToken.getOrCreateAssociatedTokenAccount(
        connection,
        senderKeypair,
        tokenPublicKey,
        senderKeypair.publicKey
      );
      const toTokenAccount = await splToken.getOrCreateAssociatedTokenAccount(
        connection,
        senderKeypair,
        tokenPublicKey,
        recipient
      );
      const transferInstruction = splToken.createTransferInstruction(
        fromTokenAccount.address,
        toTokenAccount.address,
        senderKeypair.publicKey,
        parseInt(amount * (10 ** await splToken.getMint(connection, tokenPublicKey).then(mint => mint.decimals)))
      );
      const transaction = new Transaction().add(transferInstruction);
      const signature = await sendAndConfirmTransaction(connection, transaction, [senderKeypair]);
      ctx.reply(`Successfully transferred ${amount} tokens to ${recipientAddress}. Signature: ${signature}`);
    }
  } catch (error) {
    console.error('Error in transferSolana:', error);
    ctx.reply(`Failed to transfer tokens on Solana: ${error.message}`);
  }
}

async function transferAlgorand(ctx, wallet, tokenType, tokenAddress, amount, recipientAddress) {
  try {
    const algodClient = new algosdk.Algodv2('', 'https://mainnet-api.algonode.cloud', '');
    const senderAccount = algosdk.mnemonicToSecretKey(wallet.privateKey);

    const suggestedParams = await algodClient.getTransactionParams().do();

    if (tokenType === 'native') {
      const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        from: senderAccount.addr,
        to: recipientAddress,
        amount: algosdk.algosToMicroalgos(parseFloat(amount)),
        suggestedParams,
      });

      const signedTxn = txn.signTxn(senderAccount.sk);
      const { txId } = await algodClient.sendRawTransaction(signedTxn).do();
      await algosdk.waitForConfirmation(algodClient, txId, 4);
      ctx.reply(`Successfully transferred ${amount} ALGO to ${recipientAddress}. Transaction ID: ${txId}`);
    } else {
      const assetIndex = parseInt(tokenAddress);
      const txn = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
        from: senderAccount.addr,
        to: recipientAddress,
        amount: parseInt(parseFloat(amount) * 100), // Assuming 2 decimals, adjust as needed
        assetIndex,
        suggestedParams,
      });

      const signedTxn = txn.signTxn(senderAccount.sk);
      const { txId } = await algodClient.sendRawTransaction(signedTxn).do();
      await algosdk.waitForConfirmation(algodClient, txId, 4);
      ctx.reply(`Successfully transferred ${amount} tokens to ${recipientAddress}. Transaction ID: ${txId}`);
    }
  } catch (error) {
    console.error('Error in transferAlgorand:', error);
    ctx.reply(`Failed to transfer tokens on Algorand: ${error.message}`);
  }
}

async function transferSui(ctx, wallet, tokenType, tokenAddress, amount, recipientAddress) {
  try {
    const provider = new SuiClient({ url: getFullnodeUrl('mainnet') });
    const suiPrivateKey = wallet.privateKey;

    const decodedKey = decodeSuiPrivateKey(suiPrivateKey);
    const { schema, secretKey } = decodedKey;

    if (secretKey.length !== PRIVATE_KEY_SIZE) {
      throw new Error('Wrong secretKey size. Expected 32 bytes.');
    }

    const keypair = Ed25519Keypair.fromSecretKey(secretKey);
    const { Transaction } = require('@mysten/sui/transactions');
    const tx = new Transaction();
    const amountInNanoSUI = BigInt(amount * 1e9); // Convert SUI amount to its smallest unit

    if (tokenType === 'native') {
     
    
      // Split the coins to create a new coin with the specified balance
      const [coin] = tx.splitCoins(tx.gas, [amountInNanoSUI]);
  
      // Transfer the split coin to the receiving address
      tx.transferObjects([coin], recipientAddress);
    } else {
      // Directly specify the token object ID for non-native tokens
      const tokenObjectId = tokenAddress; // Assuming tokenAddress is the object ID of the token
      const [coin] = tx.splitCoins(tx.object(tokenObjectId), [amountInNanoSUI]);
      tx.transferObjects([coin], recipientAddress);
    }

    const result = await provider.signAndExecuteTransaction({
      transaction: tx,
      signer: keypair,
    });

    ctx.reply(`Successfully transferred ${amount} ${tokenType === 'native' ? 'SUI' : 'tokens'} to ${recipientAddress}. Transaction digest: ${result.digest}`);
  } catch (error) {
    console.error('Error in transferSui:', error);
    ctx.reply(`Failed to transfer tokens on Sui: ${error.message}`);
  }
}


async function transferAptos(ctx, wallet, tokenType, tokenAddress, amount, recipientAddress) {
  try {
    const client = new AptosClient(getProviderUrl('APTOS'));
    const account = new AptosAccount(Buffer.from(wallet.privateKey, 'hex'));

    if (tokenType === 'native') {
      const payload = {
        type: "entry_function_payload",
        function: "0x1::aptos_account::transfer",
        type_arguments: [],
        arguments: [recipientAddress, (BigInt(parseFloat(amount) * 1e8)).toString()],
      };
      const txnRequest = await client.generateTransaction(account.address(), payload);
      const signedTxn = await client.signTransaction(account, txnRequest);
      const transactionRes = await client.submitTransaction(signedTxn);
      await client.waitForTransaction(transactionRes.hash);
      ctx.reply(`Successfully transferred ${amount} APT to ${recipientAddress}. Transaction hash: ${transactionRes.hash}`);
    } else {
      const payload = {
        type: "entry_function_payload",
        function: "0x1::coin::transfer",
        type_arguments: [tokenAddress],
        arguments: [recipientAddress, (BigInt(parseFloat(amount) * 1e8)).toString()],
      };
      const txnRequest = await client.generateTransaction(account.address(), payload);
      const signedTxn = await client.signTransaction(account, txnRequest);
      const transactionRes = await client.submitTransaction(signedTxn);
      await client.waitForTransaction(transactionRes.hash);
      ctx.reply(`Successfully transferred ${amount} tokens to ${recipientAddress}. Transaction hash: ${transactionRes.hash}`);
    }
  } catch (error) {
    console.error('Error in transferAptos:', error);
    ctx.reply(`Failed to transfer tokens on Aptos: ${error.message}`);
  }
}

function getMainnetProviderUrl(network) {
  const providerUrls = {
    ETHEREUM: 'https://eth-mainnet.g.alchemy.com/v2/3MMaXlOkQyjVCCW1HNbY67u_BlkXI3Ff',
    ARBITRUM: 'https://arb1.arbitrum.io/rpc',
    SCROLL: 'https://mainnet.scroll.io',
    BASE: 'https://mainnet.base.org',
    POLYGON: 'https://polygon-rpc.com',
    OPTIMISM: 'https://mainnet.optimism.io',
    BNB: 'https://bsc-dataseed.binance.org',
    SOLANAB: 'https://api.mainnet-beta.solana.com',
    SOLANA: 'https://api.mainnet.solana.com',
    ALGORAND: 'https://mainnet-api.algonode.cloud',
    SUI: 'https://fullnode.mainnet.sui.io:443',
    APTOS: 'https://fullnode.mainnet.aptoslabs.com',
 
  };

  return providerUrls[network]
}

function getProviderUrl(network) {
  const providerUrls = {
    ETHEREUM: 'https://eth-sepolia.g.alchemy.com/v2/3MMaXlOkQyjVCCW1HNbY67u_BlkXI3Ff',
    ARBITRUM: 'https://arb-sepolia.g.alchemy.com/v2/3MMaXlOkQyjVCCW1HNbY67u_BlkXI3Ff',
    SCROLL: 'https://scroll-sepolia.g.alchemy.com/v2/3MMaXlOkQyjVCCW1HNbY67u_BlkXI3Ff',
    BASE: 'https://base-sepolia.g.alchemy.com/v2/3MMaXlOkQyjVCCW1HNbY67u_BlkXI3Ff',
    POLYGON: 'https://polygon-amoy.g.alchemy.com/v2/3MMaXlOkQyjVCCW1HNbY67u_BlkXI3Ff',
    OPTIMISM: 'https://opt-sepolia.g.alchemy.com/v2/3MMaXlOkQyjVCCW1HNbY67u_BlkXI3Ff', 
    BNB: 'https://data-seed-prebsc-1-s1.binance.org:8545',
    SOLANA: 'https://api.devnet.solana.com',
    ALGORAND: 'https://testnet-api.algonode.cloud',
    SUI: 'https://fullnode.testnet.sui.io:443',
    APTOS: 'https://fullnode.testnet.aptoslabs.com', 
  };

  return providerUrls[network];
}


function decodeSuiPrivateKey(value) {
  const { prefix, words } = bech32.decode(value);
  if (prefix !== SUI_PRIVATE_KEY_PREFIX) { 
    throw new Error('Invalid private key prefix');
  }
  const extendedSecretKey = new Uint8Array(bech32.fromWords(words));
  const secretKey = extendedSecretKey.slice(1);
  const signatureScheme = SIGNATURE_FLAG_TO_SCHEME[extendedSecretKey[0]];
  return {
    schema: signatureScheme,
    secretKey: secretKey,
  };
}


async function checkBalance(ctx, userId, network, address) {

  ctx.reply(`Network: ${network}, Address: ${address}, ID: ${userId}`)
  const wallet = await WalletModel.findOne({ userId, address });
  if (!wallet) {
    throw new Error('Wallet not found'); 
  }

  switch (network) {
    case 'ETHEREUM':
    case 'ARBITRUM':
    case 'SCROLL':
    case 'BASE':
    case 'POLYGON':
    case 'OPTIMISM':
    case 'BNB':
      return await checkEVMBalance(ctx, network, address);
    case 'SOLANA':
      return await checkSolanaBalance(address);
    case 'ALGORAND':
      return await checkAlgorandBalance(address);
    case 'SUI':
      return await checkSuiBalance(address);
    case 'APTOS':
      return await checkAptosBalance(address); 
    default:
      throw new Error('Unsupported network');
  }
} 

async function checkEVMBalance(ctx,network, address) {
  ctx.reply(`Network: ${network}, Address: ${address}`)
  const provider = new ethers.providers.JsonRpcProvider(getProviderUrl(network));
  const balance = await provider.getBalance(address);
  return `${ethers.utils.formatEther(balance)} ${network}`; 
}

async function checkSolanaBalance(address) {
  const connection = new Connection(getProviderUrl('SOLANA'));
  const publicKey = new PublicKey(address);
  const balance = await connection.getBalance(publicKey);
  return `${balance / 1e9} SOL`;
}

async function checkAlgorandBalance(address) {
  const algodClient = new algosdk.Algodv2('', 'https://mainnet-api.algonode.cloud', '');
  const accountInfo = await algodClient.accountInformation(address).do();
  return `${accountInfo.amount / 1e6} ALGO`;
}

async function checkSuiBalance(address) {
  const client = new SuiClient({ url: getProviderUrl('SUI') });
  const balance = await client.getBalance({ owner: address });
  return `${Number(balance.totalBalance) / 1e9} SUI`;
}

async function checkAptosBalance(address) {
  try {
    const client = new AptosClient(getProviderUrl('APTOS'));
    const resources = await client.getAccountResources(address);
    const accountResource = resources.find(r => r.type === '0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>');
    
    if (!accountResource) {
      throw new Error('Account resource not found');
    }
    
    const balance = accountResource.data.coin.value;
    return `${Number(balance) / 1e8} APT`;
  } catch (error) {
    if (error.message.includes('account not found')) {
      return 'Error: Account not found. Please check the address and try again.';
    } else {
      return `Error checking balance: ${error.message}`;
    }
  }
}




async function bridgeNonNativeTokens(ctx, sendingNetwork, sendingAddress, tokenAddress, receivingNetwork, receivingAddress, amount) {

  ctx.reply(`Amount:${amount}, Token Address:${tokenAddress}, Sending Network:${sendingNetwork}, Sending Address:${sendingAddress}, Receiving Network:${receivingNetwork}, Receiving Address:${receivingAddress}`)
  try {
    
    const sendingChainId = getChainId(sendingNetwork);
    const receivingChainId = getChainId(receivingNetwork);

    const formattedReceivingAddress = tryNativeToUint8Array(receivingAddress, receivingChainId);

    let receipt;

    if (sendingNetwork === 'ETHEREUM' || EVM_NETWORKS.includes(sendingNetwork)) {
      const tokenBridgeAddress = tokenBridgeAddresses[sendingNetwork];
      const provider = new ethers.providers.JsonRpcProvider(getProviderUrl(sendingNetwork));
      const signer = new ethers.Wallet(wallet.privateKey, provider);

      const transferAmount = ethers.utils.parseUnits(amount, 18);

      // Step 1: Attest the token if not registered on Wormhole bridge
      const attestReceipt = await attestFromEth(tokenBridgeAddress, signer, tokenAddress);
      await attestReceipt.wait();
      ctx.reply(`Attestation transaction submitted on ${sendingNetwork}. Transaction hash: ${attestReceipt.transactionHash}`);

      // Step 2: Approve the token bridge to spend tokens
      const approveTx = await approveEth(
        tokenBridgeAddress,
        tokenAddress,
        signer,
        transferAmount
      );
      await approveTx.wait();

      // Step 3: Transfer tokens via the Wormhole bridge
      receipt = await transferFromEth(
        tokenBridgeAddress,
        signer,
        tokenAddress,
        transferAmount,
        receivingChainId,
        formattedReceivingAddress,
      );
      ctx.reply(`Bridge transaction submitted. Transaction hash: ${receipt.transactionHash}`);

    } else if (sendingNetwork === 'SOLANA') {

      // Handle non-native tokens on Solana
      const connection = new Connection(getProviderUrl('SOLANA'));
      const senderKeypair = Keypair.fromSecretKey(Buffer.from(wallet.privateKey, 'hex'));

      const bridgeAddress = new PublicKey(coreBridgeAddresses['SOLANA']);

      const tokenBridgeAddress = new PublicKey(tokenBridgeAddresses['SOLANA']);

      // Step 1: Attest the token if not registered on Wormhole bridge
      const mintAddress = new PublicKey(tokenAddress); // Convert tokenAddress to PublicKey for Solana
      const attestTx = await attestFromSolana(connection, tokenBridgeAddress, senderKeypair.publicKey, mintAddress);
      const attestSignature = await sendAndConfirmTransaction(connection, attestTx, [senderKeypair]);
      ctx.reply(`Attestation transaction submitted on Solana. Transaction signature: ${attestSignature}`);

      // Step 2: Transfer non-native tokens via the Wormhole bridge
      const transferAmount = BigInt(parseFloat(amount) * LAMPORTS_PER_SOL); // Convert to lamports
      const transaction = await transferFromSolana(
        connection,
        bridgeAddress, // Wormhole bridge address
        tokenBridgeAddress,
        senderKeypair.publicKey, // payerAddress
        senderKeypair.publicKey, // fromAddress (we use sender's address)
        mintAddress, // mintAddress (non-native token)
        transferAmount,
        formattedReceivingAddress, // Receiving address as Uint8Array
        receivingChainId
      );

      const transferSignature = await sendAndConfirmTransaction(connection, transaction, [keypair]);
      ctx.reply(`Bridge transaction submitted on Solana. Transaction signature: ${transferSignature}`);


    }   else if (sendingNetwork === 'APTOS') {
  
      // Aptos token attestation and transfer
      const transferAmount = BigInt(amount * 1e8).toString();  // Amount in Aptos smallest unit

      // Attestation
      const attestTx = await attestFromAptos(tokenBridgeAddresses.APTOS, sendingChainId, tokenAddress);
      await aptosClient.submitTransaction(attestTx);

      // Transfer
      const transferTx = await transferFromAptos(
        tokenBridgeAddresses.APTOS,
        tokenAddress, // Fully qualified type (APTOS)
        transferAmount,
        receivingChainId,
        Buffer.from(receivingAddress, 'hex')
      );
      await aptosClient.submitTransaction(transferTx);

      ctx.reply(`Bridge transaction submitted on Aptos.`);

    }  else if (sendingNetwork === 'ALGORAND') {

      // Algorand attestation and transfer
      const algodClient = new algosdk.Algodv2('', 'https://testnet-api.algonode.cloud', '');
      const transferAmount = BigInt(amount * 1e6); // Amount in microAlgos

      // Attestation
      const attestTxs = await attestFromAlgorand(algodClient, ALGOD_TOKEN_BRIDGE_ID, ALGOD_BRIDGE_ID, sendingAddress, BigInt(tokenAddress));
      await Promise.all(attestTxs.map(tx => algodClient.sendRawTransaction(tx.blob).do()));

      // Transfer
      const transferTxs = await transferFromAlgorand(algodClient, ALGOD_TOKEN_BRIDGE_ID, ALGOD_BRIDGE_ID, sendingAddress, BigInt(tokenAddress), transferAmount, receivingAddress, receivingChainId, BigInt(0));
      await Promise.all(transferTxs.map(tx => algodClient.sendRawTransaction(tx.blob).do()));

      ctx.reply(`Bridge transaction submitted on Algorand.`);

      vaa = await getSignedVAA(transferTxs, sendingChainId, receivingChainId);

    } else if (sendingNetwork === 'SUI') {
      // Sui attestation and transfer
      const provider = new JsonRpcProvider('https://fullnode.mainnet.sui.io:443');
      const transferAmount = BigInt(amount * 1e9); // Amount in SUI

      // Attestation
      const attestTx = await attestFromSui(provider, SUI_CORE_BRIDGE_OBJECT_ID, SUI_TOKEN_BRIDGE_OBJECT_ID, tokenAddress);
      await provider.executeTransactionBlock(attestTx);

      // Transfer
      const coins = [{ id: '0x123', amount: transferAmount }]; // Replace with actual coins list
      const transferTx = await transferFromSui(provider, SUI_CORE_BRIDGE_OBJECT_ID, SUI_TOKEN_BRIDGE_OBJECT_ID, coins, tokenAddress, transferAmount, receivingChainId, Buffer.from(receivingAddress, 'hex'));
      await provider.executeTransactionBlock(transferTx);

      ctx.reply(`Bridge transaction submitted on Sui.`);

   

    } else {
      ctx.reply('Unsupported sending network for USDC bridge.');
      return;
    }

 

  } catch (error) {
    console.error('Error in bridgeNonNativeTokens:', error);
    ctx.reply('An error occurred while bridging tokens. Please try again.');
  }
} 

async function bridgeUSDC(ctx, sendingNetwork, sendingAddress, receivingNetwork, receivingAddress, amount) {
  ctx.reply(`Bridging ${amount} USDC from ${sendingNetwork} (${sendingAddress}) to ${receivingNetwork} (${receivingAddress})...`);

  

  try {
    
    const sendingChainId = getChainId(sendingNetwork);
    const receivingChainId = getChainId(receivingNetwork);

    const formattedReceivingAddress = tryNativeToUint8Array(receivingAddress, receivingChainId);

    let receipt;

    if (sendingNetwork === 'ETHEREUM' || EVM_NETWORKS.includes(sendingNetwork)) {
      const tokenBridgeAddress = tokenBridgeAddresses[sendingNetwork];
      const provider = new ethers.providers.JsonRpcProvider(getProviderUrl(sendingNetwork));
      const signer = new ethers.Wallet(wallet.privateKey, provider);
      const tokenAddress = usdcAddresses[sendingNetwork];

      const transferAmount = ethers.utils.parseUnits(amount, 18);

      // Step 1: Attest the token if not registered on Wormhole bridge
      const attestReceipt = await attestFromEth(tokenBridgeAddress, signer, tokenAddress);
      await attestReceipt.wait();
      ctx.reply(`Attestation transaction submitted on ${sendingNetwork}. Transaction hash: ${attestReceipt.transactionHash}`);

      // Step 2: Approve the token bridge to spend tokens
      const approveTx = await approveEth(
        tokenBridgeAddress,
        tokenAddress,
        signer,
        transferAmount
      );
      await approveTx.wait();

      // Step 3: Transfer tokens via the Wormhole bridge
      receipt = await transferFromEth(
        tokenBridgeAddress,
        signer,
        tokenAddress,
        transferAmount,
        receivingChainId,
        formattedReceivingAddress,
      );
      ctx.reply(`Bridge transaction submitted. Transaction hash: ${receipt.transactionHash}`);

    } else if (sendingNetwork === 'SOLANA') {

      const tokenAddress = usdcAddresses[sendingNetwork];
      // Handle non-native tokens on Solana
      const connection = new Connection(getProviderUrl('SOLANA'));
      const senderKeypair = Keypair.fromSecretKey(Buffer.from(wallet.privateKey, 'hex'));

      const bridgeAddress = new PublicKey(coreBridgeAddresses['SOLANA']);

      const tokenBridgeAddress = new PublicKey(tokenBridgeAddresses['SOLANA']);

      // Step 1: Attest the token if not registered on Wormhole bridge
      const mintAddress = new PublicKey(tokenAddress); // Convert tokenAddress to PublicKey for Solana
      const attestTx = await attestFromSolana(connection, tokenBridgeAddress, senderKeypair.publicKey, mintAddress);
      const attestSignature = await sendAndConfirmTransaction(connection, attestTx, [senderKeypair]);
      ctx.reply(`Attestation transaction submitted on Solana. Transaction signature: ${attestSignature}`);

      // Step 2: Transfer non-native tokens via the Wormhole bridge
      const transferAmount = BigInt(parseFloat(amount) * LAMPORTS_PER_SOL); // Convert to lamports
      const transaction = await transferFromSolana(
        connection,
        bridgeAddress, // Wormhole bridge address
        tokenBridgeAddress,
        senderKeypair.publicKey, // payerAddress
        senderKeypair.publicKey, // fromAddress (we use sender's address)
        mintAddress, // mintAddress (non-native token)
        transferAmount,
        formattedReceivingAddress, // Receiving address as Uint8Array
        receivingChainId
      );

      const transferSignature = await sendAndConfirmTransaction(connection, transaction, [keypair]);
      ctx.reply(`Bridge transaction submitted on Solana. Transaction signature: ${transferSignature}`);


    }   else if (sendingNetwork === 'APTOS') {
      const tokenAddress = usdcAddresses[sendingNetwork];
      // Aptos token attestation and transfer
      const transferAmount = BigInt(amount * 1e8).toString();  // Amount in Aptos smallest unit

      // Attestation
      const attestTx = await attestFromAptos(tokenBridgeAddresses.APTOS, sendingChainId, tokenAddress);
      await aptosClient.submitTransaction(attestTx);

      // Transfer
      const transferTx = await transferFromAptos(
        tokenBridgeAddresses.APTOS,
        tokenAddress, // Fully qualified type (APTOS)
        transferAmount,
        receivingChainId,
        Buffer.from(receivingAddress, 'hex')
      );
      await aptosClient.submitTransaction(transferTx);

      ctx.reply(`Bridge transaction submitted on Aptos.`);

    }  else if (sendingNetwork === 'ALGORAND') {

      const tokenAddress = usdcAddresses[sendingNetwork];
      // Algorand attestation and transfer
      const algodClient = new algosdk.Algodv2('', 'https://testnet-api.algonode.cloud', '');
      const transferAmount = BigInt(amount * 1e6); // Amount in microAlgos

      // Attestation
      const attestTxs = await attestFromAlgorand(algodClient, ALGOD_TOKEN_BRIDGE_ID, ALGOD_BRIDGE_ID, sendingAddress, BigInt(tokenAddress));
      await Promise.all(attestTxs.map(tx => algodClient.sendRawTransaction(tx.blob).do()));

      // Transfer
      const transferTxs = await transferFromAlgorand(algodClient, ALGOD_TOKEN_BRIDGE_ID, ALGOD_BRIDGE_ID, sendingAddress, BigInt(tokenAddress), transferAmount, receivingAddress, receivingChainId, BigInt(0));
      await Promise.all(transferTxs.map(tx => algodClient.sendRawTransaction(tx.blob).do()));

      ctx.reply(`Bridge transaction submitted on Algorand.`);

      vaa = await getSignedVAA(transferTxs, sendingChainId, receivingChainId);

    } else if (sendingNetwork === 'SUI') {
      const tokenAddress = usdcAddresses[sendingNetwork];
      // Sui attestation and transfer
      const provider = new JsonRpcProvider('https://fullnode.mainnet.sui.io:443');
      const transferAmount = BigInt(amount * 1e9); // Amount in SUI

      // Attestation
      const attestTx = await attestFromSui(provider, SUI_CORE_BRIDGE_OBJECT_ID, SUI_TOKEN_BRIDGE_OBJECT_ID, tokenAddress);
      await provider.executeTransactionBlock(attestTx);

      // Transfer
      const coins = [{ id: '0x123', amount: transferAmount }]; // Replace with actual coins list
      const transferTx = await transferFromSui(provider, SUI_CORE_BRIDGE_OBJECT_ID, SUI_TOKEN_BRIDGE_OBJECT_ID, coins, tokenAddress, transferAmount, receivingChainId, Buffer.from(receivingAddress, 'hex'));
      await provider.executeTransactionBlock(transferTx);

      ctx.reply(`Bridge transaction submitted on Sui.`);

   

    } else {
      ctx.reply('Unsupported sending network for USDC bridge.');
      return;
    }

 

  } catch (error) {
    console.error('Error in bridgeUSDC:', error);
    ctx.reply('An error occurred while bridging USDC. Please try again.');
  }
  
}
async function bridgeNativeTokens(ctx, sendingNetwork, sendingAddress, receivingNetwork, receivingAddress, amount) {
  ctx.reply(`Bridging ${amount} from ${sendingNetwork} (${sendingAddress}) to ${receivingNetwork} (${receivingAddress})...`);
  try {
    const userId = ctx.from.id;

    // Fetch wallet for the user
    let wallet;
    if (EVM_NETWORKS.includes(sendingNetwork)) {
      wallet = await WalletModel.findOne({ userId, $or: [{ network: 'EVM' }, { network: sendingNetwork }], address: sendingAddress });
    } else {
      wallet = await WalletModel.findOne({ userId, network: sendingNetwork, address: sendingAddress });
    }

    if (!wallet) {
      ctx.reply(`No ${sendingNetwork} wallet found for your account with the address ${sendingAddress}.`);
      return;
    }

    const receivingChainId = getChainId(receivingNetwork);

    let receipt;
    let scanUrl;

    // EVM Networks (Ethereum, BNB, etc.)
    if (EVM_NETWORKS.includes(sendingNetwork)) {
      const tokenBridgeAddress = tokenBridgeAddresses[sendingNetwork];
      const provider = new ethers.providers.JsonRpcProvider(getProviderUrl(sendingNetwork));
      const signer = new ethers.Wallet(wallet.privateKey, provider);

      const transferAmount = ethers.utils.parseUnits(amount, 18);
      const formattedReceivingAddress = tryNativeToUint8Array(receivingAddress, receivingChainId);

      receipt = await transferFromEthNative(
        tokenBridgeAddress,
        signer,
        transferAmount,
        receivingChainId,
        formattedReceivingAddress,
      );

      scanUrl = `https://wormholescan.com/#/tx/${receipt.transactionHash}`;
      ctx.reply(`Bridge transaction submitted on ${sendingNetwork}. Transaction: https://wormholescan.com/#/tx/${receipt.transactionHash}`);

    } else if (sendingNetwork === 'SOLANA') {
      const connection = new Connection(getProviderUrl('SOLANA'));
      const senderKeypair = Keypair.fromSecretKey(Buffer.from(wallet.privateKey, 'hex'));
      const payerKeypair = senderKeypair; // Assuming payer and sender are the same

      const bridgeAddress = new PublicKey(coreBridgeAddresses['SOLANA']);
      const tokenBridgeAddress = new PublicKey(tokenBridgeAddresses['SOLANA']);
      const transferAmount = BigInt(parseFloat(amount) * LAMPORTS_PER_SOL);
      const formattedReceivingAddress = tryNativeToUint8Array(receivingAddress, receivingChainId);

      const transaction = await transferNativeSol(
        connection,
        bridgeAddress,
        tokenBridgeAddress,
        senderKeypair.publicKey,
        transferAmount,
        formattedReceivingAddress,
        receivingChainId
      );

      transaction.feePayer = payerKeypair.publicKey;
      const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
      transaction.recentBlockhash = blockhash;
      transaction.lastValidBlockHeight = lastValidBlockHeight;

      transaction.partialSign(payerKeypair);
      const rawTransaction = transaction.serialize();
      receipt = await connection.sendRawTransaction(rawTransaction);
      await connection.confirmTransaction(receipt);

      scanUrl = `https://wormholescan.com/#/tx/${receipt}`;

      ctx.reply(`Bridge transaction submitted on Solana. Transaction: https://wormholescan.com/#/tx/${receipt}`);

    } else if (sendingNetwork === 'APTOS') {
      const client = new AptosClient(getProviderUrl('APTOS'));
      const account = new AptosAccount(Buffer.from(wallet.privateKey, 'hex'));
      const transferAmount = BigInt(parseFloat(amount) * 1e8).toString();

      const payload = await transferFromAptos(
        tokenBridgeAddresses.APTOS,
        '0x1::aptos_coin::AptosCoin',
        transferAmount,
        receivingChainId,
        Buffer.from(receivingAddress, 'hex')
      );

      const txnRequest = await client.generateTransaction(account.address(), payload);
      const signedTxn = await client.signTransaction(account, txnRequest);
      receipt = await client.submitTransaction(signedTxn);
      await client.waitForTransaction(receipt.hash);

      scanUrl = `https://wormholescan.com/#/tx/${receipt.hash}`;

      ctx.reply(`Bridge transaction submitted on Aptos. Transaction: https://wormholescan.com/#/tx/${receipt.hash}`);

    } else if (sendingNetwork === 'ALGORAND') {
      const algodClient = new algosdk.Algodv2('', 'https://testnet-api.algonode.cloud', '');
      const senderAccount = algosdk.mnemonicToSecretKey(wallet.privateKey);
      const transferAmount = BigInt(parseFloat(amount) * 1e6);

      const transferTxs = await transferFromAlgorand(
        algodClient,
        ALGOD_TOKEN_BRIDGE_ID,
        ALGOD_BRIDGE_ID,
        sendingAddress,
        BigInt(0),
        transferAmount,
        receivingAddress,
        receivingChainId,
        BigInt(0)
      );

      const txnGroup = transferTxs.map(({ txn }) => txn);
      const groupID = algosdk.computeGroupID(txnGroup);
      txnGroup.forEach(txn => txn.group = groupID);

      const signedTxns = txnGroup.map(txn => txn.signTxn(senderAccount.sk));

      receipt = await algodClient.sendRawTransaction(signedTxns).do();

      scanUrl = `https://wormholescan.com/#/tx/${receipt.txId}`;

      ctx.reply(`Bridge transaction submitted on Algorand. Transaction: https://wormholescan.com/#/tx/${receipt.txId}`);

    } else if (sendingNetwork === 'SUI') {
      const provider = new SuiClient({ url: getProviderUrl('SUI') });
      const keypair = Ed25519Keypair.fromSecretKey(Buffer.from(wallet.privateKey, 'hex'));
      const transferAmount = BigInt(parseFloat(amount) * 1e9);

      const transferTxBlock = await transferFromSui(
        provider,
        SUI_CORE_BRIDGE_OBJECT_ID,
        SUI_TOKEN_BRIDGE_OBJECT_ID,
        [{ id: '0x2::sui::SUI', amount: transferAmount }],
        '0x2::sui::SUI',
        transferAmount,
        receivingChainId,
        Buffer.from(receivingAddress, 'hex')
      );

      const transferTx = new Transaction();
      transferTx.add(transferTxBlock);
      const { bytes: transferBytes, signature: transferSignature } = transferTx.sign({ client, signer: keypair });

      receipt = await provider.executeTransactionBlock({
        transactionBlock: transferBytes,
        signature: transferSignature,
        requestType: 'WaitForLocalExecution',
        options: { showEffects: true },
      });

      scanUrl = `https://wormholescan.com/#/tx/${receipt.digest}`;

      ctx.reply(`Bridge transaction submitted on Sui. Transaction digest: ${receipt.digest}`);

    } else {
      ctx.reply('Unsupported sending network for native token bridge.');
      return;
    }


    // Save bridge transaction data in MongoDB
    const newBridge = new BridgeModel({
      userId,
      sendingNetwork,
      sendingAddress,
      receivingNetwork,
      receivingAddress,
      amount,
      bridgeStatus: 'NOT REDEEMED',
      bridgeType: 'NATIVE',
      receipt,
      scanUrl,
      timestamp: Date.now()
    }); 

    await newBridge.save();
    ctx.reply(`Waiting for VAA signature by Wormhole guardians. Track VAA signature status in Wormhole Scan and redeem tokens after VAA is signed successfully.`);
  } catch (error) {
    console.error('Error in bridgeNativeTokens:', error);
    ctx.reply('An error occurred while bridging tokens. Please try again.');
  }
}


async function redeemNativeTokens(ctx, receipt, sendingNetwork, receivingNetwork, receivingAddress, sendingAddress) {

  const sendingChainId = getChainId(sendingNetwork);
  // Get the VAA for redemption
 const vaa = await getSignedVaa(ctx, receipt, sendingNetwork, sendingChainId);
 if (!vaa) {
   ctx.reply('Unable to find VAA for redemption. Please make sure the transaction has been processed and the VAA is emitted.');
   return;
 }

  try {
    const userId = ctx.from.id;

    let wallet;
    if (EVM_NETWORKS.includes(receivingNetwork)) {
      wallet = await WalletModel.findOne({ userId, $or: [{ network: 'EVM' }, { network: receivingNetwork }], address: receivingAddress });
    } else {
      wallet = await WalletModel.findOne({ userId, network: receivingNetwork, address: receivingAddress });
    }

    if (!wallet) {
      console.log('Wallet not found:', { userId, receivingNetwork, receivingAddress });
      ctx.reply(`No ${receivingNetwork} wallet found for your account with the address ${receivingAddress}. Please check the address and try again.`);
      return;
    }

    console.log('Found wallet:', wallet);

    if (EVM_NETWORKS.includes(receivingNetwork)) {
      const tokenBridgeAddress = tokenBridgeAddresses[receivingNetwork];
      const provider = new ethers.providers.JsonRpcProvider(getProviderUrl(receivingNetwork));
      const signer = new ethers.Wallet(wallet.privateKey, provider);

      const redeemTx = await redeemOnEthNative(tokenBridgeAddress, signer, vaa);
      const receipt = await provider.waitForTransaction(redeemTx.transactionHash);
      ctx.reply(`Tokens redeemed on ${receivingNetwork}. Transaction hash: ${receipt.transactionHash}`);

    } else if (receivingNetwork === 'SOLANA') {  
      const connection = new Connection(getProviderUrl('SOLANA')); 
      const payerKeypair = Keypair.fromSecretKey(Buffer.from(wallet.privateKey, 'hex'));

      const bridgeAddress = new PublicKey(coreBridgeAddresses['SOLANA']);
      const tokenBridgeAddress = new PublicKey(tokenBridgeAddresses['SOLANA']);

   const postVaatx =   await postVaaSolana(
        connection,
        payerKeypair,
        bridgeAddress,
        payerKeypair.publicKey,
        vaa
        );
        if (!postVaatx) {
          console.log('Failed to post VAA on Solana');
          ctx.reply('Failed to post VAA on Solana. Please try again.');
          return;
        }

        ctx.reply('VAA signed')

      const redeemTx = await redeemOnSolana(
        connection,
        bridgeAddress,
        tokenBridgeAddress,   
        payerKeypair.publicKey,
        vaa
      );
      const signature = await sendAndConfirmTransaction(connection, redeemTx, [payerKeypair]);
      ctx.reply(`Tokens redeemed on Solana. Transaction signature: ${signature}`);

    } else if (receivingNetwork === 'APTOS') {
      const client = new AptosClient(getProviderUrl('APTOS'));
      const account = new AptosAccount(Buffer.from(wallet.privateKey, 'hex'));

      const payload = await redeemOnAptos(client, tokenBridgeAddresses.APTOS, vaa);
      const txnRequest = await client.generateTransaction(account.address(), payload);
      const signedTxn = await client.signTransaction(account, txnRequest);
      const transactionRes = await client.submitTransaction(signedTxn);
      await client.waitForTransaction(transactionRes.hash);

      ctx.reply(`Tokens redeemed on Aptos. Transaction hash: ${transactionRes.hash}`);

    } else if (receivingNetwork === 'ALGORAND') {
      const algodClient = new algosdk.Algodv2('', 'https://testnet-api.algonode.cloud', '');
      const senderAccount = algosdk.mnemonicToSecretKey(wallet.privateKey);

      const redeemTxs = await redeemOnAlgorand(
        algodClient,
        ALGOD_TOKEN_BRIDGE_ID,
        ALGOD_BRIDGE_ID,
        vaa,
        sendingAddress
      );

      const txnGroup = redeemTxs.map(({ txn }) => txn);
      const groupID = algosdk.computeGroupID(txnGroup);
      txnGroup.forEach(txn => txn.group = groupID);

      const signedTxns = txnGroup.map(txn => txn.signTxn(senderAccount.sk));

      const sendTx = await algodClient.sendRawTransaction(signedTxns).do();
      ctx.reply(`Tokens redeemed on Algorand. Transaction ID: ${sendTx.txId}`);

    } else if (receivingNetwork === 'SUI') {
      const provider = new SuiClient({ url: getProviderUrl('SUI') });
      const keypair = Ed25519Keypair.fromSecretKey(Buffer.from(wallet.privateKey, 'hex'));

      const redeemTx = await redeemOnSui(
        provider,
        SUI_CORE_BRIDGE_OBJECT_ID,
        SUI_TOKEN_BRIDGE_OBJECT_ID,
        vaa
      );
      const redeemerTx = new Transaction();

      redeemerTx.add(redeemTx);
      const { bytes: redeemerBytes, signature: redeemerSignature } = redeemerTx.sign({ client, signer: keypair });

      const result = await provider.executeTransactionBlock({
          transactionBlock: redeemerBytes,
          signature: redeemerSignature,
          requestType: 'WaitForLocalExecution',
          options: { showEffects: true },
      });
      ctx.reply(`Tokens redeemed on Sui. Transaction digest: ${result.digest}`);

    } else {
      ctx.reply(`Redeem logic for ${receivingNetwork} is not supported yet.`);
    }

  } catch (error) {
    console.error('Error in redeemTokens:', error);
    ctx.reply('An error occurred while redeeming tokens. Please try again.');
  }
}

async function getSignedVaa(ctx, receipt, sendingNetwork, sendingChainId) {
  ctx.reply('Getting signed VAA');

  try {

    let sequence;
    let emitterAddress;

    if (sendingNetwork === 'SOLANA') {
      const connection = new Connection(getProviderUrl('SOLANA'));
      const tokenBridgeAddress = new PublicKey(tokenBridgeAddresses['SOLANA']);
      const info = await connection.getTransaction(receipt);
      sequence = parseSequenceFromLogSolana(info);
      emitterAddress = await getEmitterAddressSolana(tokenBridgeAddress);

    } else if (sendingNetwork === 'ALGORAND') {
      sequence = parseSequenceFromLogAlgorand(receipt);
      emitterAddress = getEmitterAddressAlgorand(ALGOD_TOKEN_BRIDGE_ID);

    } else if (sendingNetwork === 'SUI') {
      const originalCoreBridgePackageId = coreBridgeAddresses['SUI'];
      const transactionDigest = receipt.digest;
      const provider = new SuiClient({ url: getProviderUrl('SUI') });
      const txDetails = await provider.getTransactionBlock(transactionDigest);
      ({ emitterAddress, sequence } = getEmitterAddressAndSequenceFromResponseSui(originalCoreBridgePackageId, txDetails));

    } else if (sendingNetwork === 'APTOS') { 
      const client = new AptosClient(getProviderUrl('APTOS')); 
      const aptosTxInfo = await client.getTransactionByHash(receipt.hash);
      const coreBridgeAddress = tokenBridgeAddresses.APTOS;
      sequence = parseSequenceFromLogAptos(coreBridgeAddress, aptosTxInfo);
      emitterAddress = APTOS_TOKEN_BRIDGE_EMITTER_ADDRESS;

    } else if (EVM_NETWORKS.includes(sendingNetwork)) {
      const ETH_BRIDGE_ADDRESS = coreBridgeAddresses[sendingNetwork];
      const ETH_TOKEN_BRIDGE_ADDRESS = tokenBridgeAddresses[sendingNetwork];
      sequence = parseSequenceFromLogEth(receipt, ETH_BRIDGE_ADDRESS);
      emitterAddress = getEmitterAddressEth(ETH_TOKEN_BRIDGE_ADDRESS);
    

    } else {
      throw new Error(`Unsupported sending network: ${sendingNetwork}`);
    }
    ctx.reply(`Emitter: ${emitterAddress}, Sequencer: ${sequence}`);
 
      // Fetch the VAA
      const response = await axios.get(`https://api.testnet.wormholescan.io/api/v1/vaas/${sendingChainId}/${emitterAddress}/${sequence}`);
    
      if (response.status !== 200) {
        throw new Error(`HTTP Error: ${response.status} ${response.statusText}`);
      }
  
      const vaaData = response.data.data;
      const vaaBytes = Buffer.from(vaaData.vaa, 'base64');
  
      console.log('Signed VAA (bytes):', vaaBytes);
      console.log('Signed VAA (hex):', vaaBytes.toString('hex'));

      ctx.reply(`Signed VAA (hex): ${vaaBytes.toString('hex')}`)
  
      return vaaBytes;
 
  } catch (error) {
    console.error('Error in getting signed VAA:', error);
    ctx.reply('VAA not signed yet. Please try again later.');
    throw error;
  }
}





async function redeemUSDC(ctx, receipt, sendingNetwork, receivingNetwork, receivingAddress, sendingAddress) {

  const sendingChainId = getChainId(sendingNetwork);
  // Get the VAA for redemption
 const vaa = await getSignedVaa(ctx, receipt, sendingNetwork, sendingChainId);
 if (!vaa) {
   ctx.reply('Unable to find VAA for redemption. Please make sure the transaction has been processed and the VAA is emitted.');
   return;
 }

  try {
    const userId = ctx.from.id;

    let wallet;
    if (EVM_NETWORKS.includes(receivingNetwork)) {
      wallet = await WalletModel.findOne({ userId, $or: [{ network: 'EVM' }, { network: receivingNetwork }], address: receivingAddress });
    } else {
      wallet = await WalletModel.findOne({ userId, network: receivingNetwork, address: receivingAddress });
    }

    if (!wallet) {
      console.log('Wallet not found:', { userId, receivingNetwork, receivingAddress });
      ctx.reply(`No ${receivingNetwork} wallet found for your account with the address ${receivingAddress}. Please check the address and try again.`);
      return;
    }

    console.log('Found wallet:', wallet);

    if (EVM_NETWORKS.includes(receivingNetwork)) {
      const tokenBridgeAddress = tokenBridgeAddresses[receivingNetwork];
      const provider = new ethers.providers.JsonRpcProvider(getProviderUrl(receivingNetwork));
      const signer = new ethers.Wallet(wallet.privateKey, provider);

      const redeemTx = await redeemOnEth(tokenBridgeAddress, signer, vaa);
      const receipt = await provider.waitForTransaction(redeemTx.transactionHash);
      ctx.reply(`Tokens redeemed on ${receivingNetwork}. Transaction hash: ${receipt.transactionHash}`);

    } else if (receivingNetwork === 'SOLANA') {  
      const connection = new Connection(getProviderUrl('SOLANA')); 
      const payerKeypair = Keypair.fromSecretKey(Buffer.from(wallet.privateKey, 'hex'));

      const bridgeAddress = new PublicKey(coreBridgeAddresses['SOLANA']);
      const tokenBridgeAddress = new PublicKey(tokenBridgeAddresses['SOLANA']);

   const postVaatx =   await postVaaSolana(
        connection,
        payerKeypair,
        bridgeAddress,
        payerKeypair.publicKey,
        vaa
        );
        if (!postVaatx) {
          console.log('Failed to post VAA on Solana');
          ctx.reply('Failed to post VAA on Solana. Please try again.');
          return;
        }

        ctx.reply('VAA signed')

      const redeemTx = await redeemOnSolana(
        connection,
        bridgeAddress,
        tokenBridgeAddress,   
        payerKeypair.publicKey,
        vaa
      );
      const signature = await sendAndConfirmTransaction(connection, redeemTx, [payerKeypair]);
      ctx.reply(`Tokens redeemed on Solana. Transaction signature: ${signature}`);

    } else if (receivingNetwork === 'APTOS') {
      const client = new AptosClient(getProviderUrl('APTOS'));
      const account = new AptosAccount(Buffer.from(wallet.privateKey, 'hex'));

      const payload = await redeemOnAptos(client, tokenBridgeAddresses.APTOS, vaa);
      const txnRequest = await client.generateTransaction(account.address(), payload);
      const signedTxn = await client.signTransaction(account, txnRequest);
      const transactionRes = await client.submitTransaction(signedTxn);
      await client.waitForTransaction(transactionRes.hash);

      ctx.reply(`Tokens redeemed on Aptos. Transaction hash: ${transactionRes.hash}`);

    } else if (receivingNetwork === 'ALGORAND') {
      const algodClient = new algosdk.Algodv2('', 'https://testnet-api.algonode.cloud', '');
      const senderAccount = algosdk.mnemonicToSecretKey(wallet.privateKey);

      const redeemTxs = await redeemOnAlgorand(
        algodClient,
        ALGOD_TOKEN_BRIDGE_ID,
        ALGOD_BRIDGE_ID,
        vaa,
        sendingAddress
      );

      const txnGroup = redeemTxs.map(({ txn }) => txn);
      const groupID = algosdk.computeGroupID(txnGroup);
      txnGroup.forEach(txn => txn.group = groupID);

      const signedTxns = txnGroup.map(txn => txn.signTxn(senderAccount.sk));

      const sendTx = await algodClient.sendRawTransaction(signedTxns).do();
      ctx.reply(`Tokens redeemed on Algorand. Transaction ID: ${sendTx.txId}`);

    } else if (receivingNetwork === 'SUI') {
      const provider = new SuiClient({ url: getProviderUrl('SUI') });
      const keypair = Ed25519Keypair.fromSecretKey(Buffer.from(wallet.privateKey, 'hex'));

      const redeemTx = await redeemOnSui(
        provider,
        SUI_CORE_BRIDGE_OBJECT_ID,
        SUI_TOKEN_BRIDGE_OBJECT_ID,
        vaa
      );
      const redeemerTx = new Transaction();

      redeemerTx.add(redeemTx);
      const { bytes: redeemerBytes, signature: redeemerSignature } = redeemerTx.sign({ client, signer: keypair });

      const result = await provider.executeTransactionBlock({
          transactionBlock: redeemerBytes,
          signature: redeemerSignature,
          requestType: 'WaitForLocalExecution',
          options: { showEffects: true },
      });
      ctx.reply(`Tokens redeemed on Sui. Transaction digest: ${result.digest}`);

    } else {
      ctx.reply(`Redeem logic for ${receivingNetwork} is not supported yet.`);
    }

  } catch (error) {
    console.error('Error in redeemTokens:', error);
    ctx.reply('An error occurred while redeeming tokens. Please try again.');
  }
}

async function redeemTokens(ctx, receipt, sendingNetwork, receivingNetwork, receivingAddress, sendingAddress) {

  const sendingChainId = getChainId(sendingNetwork);
  // Get the VAA for redemption
 const vaa = await getSignedVaa(ctx, receipt, sendingNetwork, sendingChainId);
 if (!vaa) {
   ctx.reply('Unable to find VAA for redemption. Please make sure the transaction has been processed and the VAA is emitted.');
   return;
 }

  try {
    const userId = ctx.from.id;

    let wallet;
    if (EVM_NETWORKS.includes(receivingNetwork)) {
      wallet = await WalletModel.findOne({ userId, $or: [{ network: 'EVM' }, { network: receivingNetwork }], address: receivingAddress });
    } else {
      wallet = await WalletModel.findOne({ userId, network: receivingNetwork, address: receivingAddress });
    }

    if (!wallet) {
      console.log('Wallet not found:', { userId, receivingNetwork, receivingAddress });
      ctx.reply(`No ${receivingNetwork} wallet found for your account with the address ${receivingAddress}. Please check the address and try again.`);
      return;
    }

    console.log('Found wallet:', wallet);

    if (EVM_NETWORKS.includes(receivingNetwork)) {
      const tokenBridgeAddress = tokenBridgeAddresses[receivingNetwork];
      const provider = new ethers.providers.JsonRpcProvider(getProviderUrl(receivingNetwork));
      const signer = new ethers.Wallet(wallet.privateKey, provider);

      const redeemTx = await redeemOnEth(tokenBridgeAddress, signer, vaa);
      const receipt = await provider.waitForTransaction(redeemTx.transactionHash);
      ctx.reply(`Tokens redeemed on ${receivingNetwork}. Transaction hash: ${receipt.transactionHash}`);

    } else if (receivingNetwork === 'SOLANA') {  
      const connection = new Connection(getProviderUrl('SOLANA')); 
      const payerKeypair = Keypair.fromSecretKey(Buffer.from(wallet.privateKey, 'hex'));

      const bridgeAddress = new PublicKey(coreBridgeAddresses['SOLANA']);
      const tokenBridgeAddress = new PublicKey(tokenBridgeAddresses['SOLANA']);

   const postVaatx =   await postVaaSolana(
        connection,
        payerKeypair,
        bridgeAddress,
        payerKeypair.publicKey,
        vaa
        );
        if (!postVaatx) {
          console.log('Failed to post VAA on Solana');
          ctx.reply('Failed to post VAA on Solana. Please try again.');
          return;
        }

        ctx.reply('VAA signed')

      const redeemTx = await redeemOnSolana(
        connection,
        bridgeAddress,
        tokenBridgeAddress,   
        payerKeypair.publicKey,
        vaa
      );
      const signature = await sendAndConfirmTransaction(connection, redeemTx, [payerKeypair]);
      ctx.reply(`Tokens redeemed on Solana. Transaction signature: ${signature}`);

    } else if (receivingNetwork === 'APTOS') {
      const client = new AptosClient(getProviderUrl('APTOS'));
      const account = new AptosAccount(Buffer.from(wallet.privateKey, 'hex'));

      const payload = await redeemOnAptos(client, tokenBridgeAddresses.APTOS, vaa);
      const txnRequest = await client.generateTransaction(account.address(), payload);
      const signedTxn = await client.signTransaction(account, txnRequest);
      const transactionRes = await client.submitTransaction(signedTxn);
      await client.waitForTransaction(transactionRes.hash);

      ctx.reply(`Tokens redeemed on Aptos. Transaction hash: ${transactionRes.hash}`);

    } else if (receivingNetwork === 'ALGORAND') {
      const algodClient = new algosdk.Algodv2('', 'https://testnet-api.algonode.cloud', '');
      const senderAccount = algosdk.mnemonicToSecretKey(wallet.privateKey);

      const redeemTxs = await redeemOnAlgorand(
        algodClient,
        ALGOD_TOKEN_BRIDGE_ID,
        ALGOD_BRIDGE_ID,
        vaa,
        sendingAddress
      );

      const txnGroup = redeemTxs.map(({ txn }) => txn);
      const groupID = algosdk.computeGroupID(txnGroup);
      txnGroup.forEach(txn => txn.group = groupID);

      const signedTxns = txnGroup.map(txn => txn.signTxn(senderAccount.sk));

      const sendTx = await algodClient.sendRawTransaction(signedTxns).do();
      ctx.reply(`Tokens redeemed on Algorand. Transaction ID: ${sendTx.txId}`);

    } else if (receivingNetwork === 'SUI') {
      const provider = new SuiClient({ url: getProviderUrl('SUI') });
      const keypair = Ed25519Keypair.fromSecretKey(Buffer.from(wallet.privateKey, 'hex'));

      const redeemTx = await redeemOnSui(
        provider,
        SUI_CORE_BRIDGE_OBJECT_ID,
        SUI_TOKEN_BRIDGE_OBJECT_ID,
        vaa
      );
      const redeemerTx = new Transaction();

      redeemerTx.add(redeemTx);
      const { bytes: redeemerBytes, signature: redeemerSignature } = redeemerTx.sign({ client, signer: keypair });

      const result = await provider.executeTransactionBlock({
          transactionBlock: redeemerBytes,
          signature: redeemerSignature,
          requestType: 'WaitForLocalExecution',
          options: { showEffects: true },
      });
      ctx.reply(`Tokens redeemed on Sui. Transaction digest: ${result.digest}`);

    } else {
      ctx.reply(`Redeem logic for ${receivingNetwork} is not supported yet.`);
    }

  } catch (error) {
    console.error('Error in redeemTokens:', error);
    ctx.reply('An error occurred while redeeming tokens. Please try again.');
  }
}
function getChainId(network) {
  const chainIds = {
    ETHEREUM: CHAIN_ID_SEPOLIA,
    SOLANA: CHAIN_ID_SOLANA,
    BNB: CHAIN_ID_BSC,
    SUI: CHAIN_ID_SUI,
    ALGORAND: CHAIN_ID_ALGORAND,
    APTOS: CHAIN_ID_APTOS,
    ARBITRUM: CHAIN_ID_ARBITRUM_SEPOLIA,
    OPTIMISM: CHAIN_ID_OPTIMISM_SEPOLIA,
    SCROLL: CHAIN_ID_SCROLL,
    BASE: CHAIN_ID_BASE_SEPOLIA,   
    POLYGON: CHAIN_ID_POLYGON_SEPOLIA,
    // Add more chain IDs for other supported networks
  };
  return chainIds[network];
}

// Token bridge addresses for all supported networks
const tokenBridgeAddresses = {
  ETHEREUM: '0xDB5492265f6038831E89f495670FF909aDe94bd9', // Ethereum
  BNB: '0x9dcF9D205C9De35334D646BeE44b2D2859712A09', // BNB
  POLYGON: '0xC7A204bDBFe983FCD8d8E61D02b475D4073fF97e', // Polygon
  ARBITRUM: '0x23908A62110e21C04F3A4e011d24F901F911744A', // Arbitrum
  OPTIMISM: '0xC7A204bDBFe983FCD8d8E61D02b475D4073fF97e', // Optimism
  SCROLL: '0x22427d90B7dA3fA4642F7025A854c7254E4e45BF', // Scroll
  BASE: '0xA31aa3FDb7aF7Db93d18DDA4e19F811342EDF780', // Base
  SOLANA: 'DZnkkTmCiFWfYTfT41X3Rd1kDgozqzxWaHqsw6W4x2oe', // Solana
  ALGORAND: '000000', // Algorand token bridge
  SUI: '000000', // SUI token bridge
  APTOS: '0x576410486a2da45eee6c949c995670112ddf2fbeedab20350d506328eefc9d4f', // Aptos token bridge
  // Add other networks as necessary
};

const coreBridgeAddresses = {
  ETHEREUM: '0x4a8bc80Ed5a4067f1CCf107057b8270E0cC11A78', // Ethereum
  BNB: '0x68605AD7b15c732a30b1BbC62BE8F2A509D74b4D', // BNB
  POLYGON: '0x6b9C8671cdDC8dEab9c719bB87cBd3e782bA6a35', // Polygon
  ARBITRUM: '0xC7A204bDBFe983FCD8d8E61D02b475D4073fF97e', // Arbitrum
  OPTIMISM: '0x6b9C8671cdDC8dEab9c719bB87cBd3e782bA6a35', // Optimism
  SCROLL: '0x055F47F1250012C6B20c436570a76e52c17Af2D5', // Scroll
  BASE: '0x23908A62110e21C04F3A4e011d24F901F911744A', // Base
  SOLANA: '3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5', // Solana
  ALGORAND: '000000', // Algorand token bridge
  SUI: '000000', // SUI token bridge
  APTOS: '0x0000x5bc11445584a763c1fa7ed39081f1b920954da14e04b32440cba863d03e19625', // Aptos token bridge
  // Add other networks as necessary
};

const usdcAddresses = {
  ETHEREUM: '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238', // Ethereum
  BNB: '', // BNB
  POLYGON: '', // Polygon
  ARBITRUM: '0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d', // Arbitrum
  OPTIMISM: '0x5fd84259d66Cd46123540766Be93DFE6D43130D7', // Optimism
  SCROLL: '', // Scroll
  BASE: '0x036CbD53842c5426634e7929541eC2318f3dCF7e', // Base
  SOLANA: '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU', // Solana
  ALGORAND: '	10458941', // Algorand 
  SUI: '0xa1ec7fc00a6f40db9693ad1415d0c193ad3906494428cf252621037bd7117e29::usdc::USDC', // SUI 
  APTOS: '', // Aptos 
  // Add other networks as necessary
};


// Algorand bridge IDs (replace with actual values)
const ALGOD_TOKEN_BRIDGE_ID = BigInt('86525623');
const ALGOD_BRIDGE_ID = BigInt('86525641');

// Sui Object IDs (replace with actual values)
const SUI_CORE_BRIDGE_OBJECT_ID = '0x31358d198147da50db32eda2562951d53973a0c0ad5ed738e9b17d88b213d790';
const SUI_TOKEN_BRIDGE_OBJECT_ID = '0x6fb10cdb7aa299e9a4308752dadecb049ff55a892de92992a1edbd7912b3d6da';

const aptosClient = new AptosClient(getProviderUrl('APTOS'));


module.exports = {
  transferToken, 
  createWallet, 
  importWallet,
  checkBalance,
  bridgeNativeTokens,
  bridgeNonNativeTokens,
  bridgeUSDC, 
  redeemNativeTokens,
  redeemTokens,
  redeemUSDC, 

}
