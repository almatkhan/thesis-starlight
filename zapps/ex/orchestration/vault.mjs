/* eslint-disable prettier/prettier, camelcase, prefer-const, no-unused-vars */
import config from 'config';
import utils from 'zkp-utils';
import GN from 'general-number';
import fs from 'fs';
        

import { getContractInstance, getContractAddress, registerKey } from './common/contract.mjs';
import { storeCommitment, getCurrentWholeCommitment, getCommitmentsById, getAllCommitments, getInputCommitments, joinCommitments, splitCommitments, markNullified,getnullifierMembershipWitness,getupdatedNullifierPaths,temporaryUpdateNullifier,updateNullifierTree} from './common/commitment-storage.mjs';
import { generateProof } from './common/zokrates.mjs';
import { getMembershipWitness, getRoot } from './common/timber.mjs';
import { decompressStarlightKey, compressStarlightKey, encrypt, decrypt, poseidonHash, scalarMult } from './common/number-theory.mjs';
        

const { generalise } = GN;
const db = '/app/orchestration/common/db/preimage.json';
const keyDb = '/app/orchestration/common/db/key.json';


            
 async  vault(__amountIn, _balances_msgSender_newOwnerPublicKey = 0) {
	
      const instance = this.instance;
      const contractAddr = this.contractAddr;
      const web3 =  this.web3;
              
const msgValue = 0;
const _amountIn = generalise(__amountIn);
let balances_msgSender_newOwnerPublicKey = generalise(_balances_msgSender_newOwnerPublicKey);
        

// Read dbs for keys and previous commitment values:
        
if (!fs.existsSync(keyDb)) await registerKey(utils.randomHex(31), 'ZKSenderShield', false);
        const keys = JSON.parse(
                    fs.readFileSync(keyDb, 'utf-8', err => {
                      console.log(err);
                    }),
                  );
                const secretKey = generalise(keys.secretKey);
                const publicKey = generalise(keys.publicKey);
               


            

// read preimage for incremented state
            balances_msgSender_newOwnerPublicKey = _balances_msgSender_newOwnerPublicKey === 0 ? publicKey : balances_msgSender_newOwnerPublicKey;
            
let balances_msgSender_stateVarIdInit = 77;

const balances_msgSender_stateVarId_key = generalise(config.web3.options.defaultAccount); // emulates msg.sender

let balances_msgSender_stateVarId = generalise(utils.mimcHash([generalise(balances_msgSender_stateVarIdInit).bigInt, balances_msgSender_stateVarId_key.bigInt], 'ALT_BN_254')).hex(32);
            
const balances_msgSender_newCommitmentValue = generalise(parseInt(_amountIn.integer, 10));
            



// non-secret line would go here but has been filtered out


// non-secret line would go here but has been filtered out


// increment would go here but has been filtered out


// non-secret line would go here but has been filtered out

true



// Calculate commitment(s): 

          
const balances_msgSender_newSalt = generalise(utils.randomHex(31));
          
let balances_msgSender_newCommitment = poseidonHash([BigInt(balances_msgSender_stateVarId), BigInt(balances_msgSender_newCommitmentValue.hex(32)), BigInt(balances_msgSender_newOwnerPublicKey.hex(32)), BigInt(balances_msgSender_newSalt.hex(32))],);
          
balances_msgSender_newCommitment = generalise(balances_msgSender_newCommitment.hex(32)); // truncate



// Call Zokrates to generate the proof:
          
const allInputs = [
              	_amountIn.integer,
								balances_msgSender_stateVarId_key.integer,
              	balances_msgSender_newOwnerPublicKey.integer,
              	balances_msgSender_newSalt.integer,
              	balances_msgSender_newCommitment.integer
              
            ,
].flat(Infinity);
const res = await generateProof('vault', allInputs);
const proof = generalise(Object.values(res.proof).flat(Infinity))
          .map(coeff => coeff.integer)
          .flat(Infinity);

let BackupData = [];


// Encrypt pre-image for state variable balances_msgSender as a backup: 
 
    let balances_msgSender_ephSecretKey = generalise(utils.randomHex(31)); 
 
    let balances_msgSender_ephPublicKeyPoint = generalise(
      scalarMult(balances_msgSender_ephSecretKey.hex(32), config.BABYJUBJUB.GENERATOR)); 

    let balances_msgSender_ephPublicKey = compressStarlightKey(balances_msgSender_ephPublicKeyPoint); 

    while (balances_msgSender_ephPublicKey === null) { 

      balances_msgSender_ephSecretKey = generalise(utils.randomHex(31)); 

      balances_msgSender_ephPublicKeyPoint = generalise(
        scalarMult(balances_msgSender_ephSecretKey.hex(32), config.BABYJUBJUB.GENERATOR)
      ); 

      balances_msgSender_ephPublicKey = compressStarlightKey(balances_msgSender_ephPublicKeyPoint);

    } 
   
    const balances_msgSender_bcipherText = encrypt(
      [BigInt(balances_msgSender_newSalt.hex(32)), BigInt(balances_msgSender_stateVarId_key.hex(32)),
          BigInt(generalise(balances_msgSender_stateVarIdInit).hex(32)), 
          BigInt(balances_msgSender_newCommitmentValue.hex(32))],
      balances_msgSender_ephSecretKey.hex(32), [
        decompressStarlightKey(balances_msgSender_newOwnerPublicKey)[0].hex(32),
        decompressStarlightKey(balances_msgSender_newOwnerPublicKey)[1].hex(32)
      ]); 

      let balances_msgSender_cipherText_combined = {varName: "balances a u", cipherText:  balances_msgSender_bcipherText, ephPublicKey: balances_msgSender_ephPublicKey.hex(32)};
 
      BackupData.push(balances_msgSender_cipherText_combined);



// Send transaction to the blockchain:
          
const txData = await instance.methods
          .vault(_amountIn.integer, {customInputs: [1], nullifierRoot:  0 ,  latestNullifierRoot: 0,  newNullifiers:  [],    commitmentRoot: 0 ,  newCommitments: [balances_msgSender_newCommitment.integer],  cipherText: [],   encKeys:  [], }, proof, BackupData).encodeABI();
          
	let txParams = {
            from: config.web3.options.defaultAccount,
            to: contractAddr,
            gas: config.web3.options.defaultGas,
            gasPrice: config.web3.options.defaultGasPrice,
            data: txData,
            chainId: await web3.eth.net.getId(),
            };
            
 	const key = config.web3.key;
            
 	const signed = await web3.eth.accounts.signTransaction(txParams, key);
            
 	const sendTxn = await web3.eth.sendSignedTransaction(signed.rawTransaction);
            
  let tx = await instance.getPastEvents("NewLeaves");
            
 tx = tx[0];

            
 if (!tx) {
              throw new Error( 'Tx failed - the commitment was not accepted on-chain, or the contract is not deployed.');
            } 

            let encEvent = '';
            
 try {
            
  encEvent = await instance.getPastEvents("EncryptedData");
            
 } catch (err) {
            
  console.log('No encrypted event');
            
}
            
let encBackupEvent = '';
            
 try {
            
  encBackupEvent = await instance.getPastEvents("EncryptedBackupData");
            
 } catch (err) {
            
  console.log('No encrypted backup event');
            
}


// Write new commitment preimage to db: 

          
await storeCommitment({
            hash: balances_msgSender_newCommitment,
            name: 'balances',
            mappingKey: balances_msgSender_stateVarId_key.integer,
            preimage: {
              	stateVarId: generalise(balances_msgSender_stateVarId),
              	value: balances_msgSender_newCommitmentValue,
              	salt: balances_msgSender_newSalt,
              	publicKey: balances_msgSender_newOwnerPublicKey,
            },
            secretKey: balances_msgSender_newOwnerPublicKey.integer === publicKey.integer ? secretKey: null,
            isNullified: false,
          });

 const bool = true; 
 return  { tx, encEvent, encBackupEvent, bool: bool };
            
}