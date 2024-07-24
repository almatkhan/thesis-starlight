/* eslint-disable prettier/prettier, camelcase, prefer-const, no-unused-vars */
import config from "config";
import utils from "zkp-utils";
import GN from "general-number";
import fs from "fs";

import {
	getContractInstance,
	getContractAddress,
	registerKey,
} from "./common/contract.mjs";
import {
	storeCommitment,
	getCurrentWholeCommitment,
	getCommitmentsById,
	getAllCommitments,
	getInputCommitments,
	joinCommitments,
	splitCommitments,
	markNullified,
	getnullifierMembershipWitness,
	getupdatedNullifierPaths,
	temporaryUpdateNullifier,
	updateNullifierTree,
} from "./common/commitment-storage.mjs";
import { generateProof } from "./common/zokrates.mjs";
import { getMembershipWitness, getRoot } from "./common/timber.mjs";
import {
	decompressStarlightKey,
	compressStarlightKey,
	encrypt,
	decrypt,
	poseidonHash,
	scalarMult,
} from "./common/number-theory.mjs";

const { generalise } = GN;
const db = "/app/orchestration/common/db/preimage.json";
const keyDb = "/app/orchestration/common/db/key.json";

export class UnVaultManager {
	constructor(web3) {
		this.web3 = web3;
	}

	async init() {
		this.instance = await getContractInstance("ZKSenderShield");
		this.contractAddr = await getContractAddress("ZKSenderShield");
	}

	async unVault(
		_amountOut,
		_balances_msgSender_newOwnerPublicKey = 0,
		_balances_msgSender_0_oldCommitment = 0,
		_balances_msgSender_1_oldCommitment = 0
	) {
		const instance = this.instance;
		const contractAddr = this.contractAddr;
		const web3 = this.web3;

		const msgValue = 0;
		const amountOut = generalise(_amountOut);
		let balances_msgSender_newOwnerPublicKey = generalise(
			_balances_msgSender_newOwnerPublicKey
		);

		// Read dbs for keys and previous commitment values:

		if (!fs.existsSync(keyDb))
			await registerKey(utils.randomHex(31), "ZKSenderShield", false);
		const keys = JSON.parse(
			fs.readFileSync(keyDb, "utf-8", (err) => {
				console.log(err);
			})
		);
		const secretKey = generalise(keys.secretKey);
		const publicKey = generalise(keys.publicKey);

		// read preimage for decremented state

		balances_msgSender_newOwnerPublicKey =
			_balances_msgSender_newOwnerPublicKey === 0
				? publicKey
				: balances_msgSender_newOwnerPublicKey;

		let balances_msgSender_stateVarIdInit = 11;

		const balances_msgSender_stateVarId_key = generalise(
			config.web3.options.defaultAccount
		); // emulates msg.sender

		let balances_msgSender_stateVarId = generalise(
			utils.mimcHash(
				[
					generalise(balances_msgSender_stateVarIdInit).bigInt,
					balances_msgSender_stateVarId_key.bigInt,
				],
				"ALT_BN_254"
			)
		).hex(32);

		let balances_msgSender_preimage = await getCommitmentsById(
			balances_msgSender_stateVarId
		);

		const balances_msgSender_newCommitmentValue = generalise(
			parseInt(amountOut.integer, 10)
		);
		// First check if required commitments exist or not

		let [
			balances_msgSender_commitmentFlag,
			balances_msgSender_0_oldCommitment,
			balances_msgSender_1_oldCommitment,
		] = getInputCommitments(
			publicKey.hex(32),
			balances_msgSender_newCommitmentValue.integer,
			balances_msgSender_preimage
		);

		let balances_msgSender_witness_0;

		let balances_msgSender_witness_1;

		if (
			balances_msgSender_1_oldCommitment === null &&
			balances_msgSender_commitmentFlag
		) {
			balances_msgSender_witness_0 = await getMembershipWitness(
				"ZKSenderShield",
				generalise(balances_msgSender_0_oldCommitment._id).integer
			);

			const tx = await splitCommitments(
				"ZKSenderShield",
				"balances",
				balances_msgSender_newCommitmentValue,
				secretKey,
				publicKey,
				[11, balances_msgSender_stateVarId_key],
				balances_msgSender_0_oldCommitment,
				balances_msgSender_witness_0,
				instance,
				contractAddr,
				web3
			);
			balances_msgSender_preimage = await getCommitmentsById(
				balances_msgSender_stateVarId
			);

			[
				balances_msgSender_commitmentFlag,
				balances_msgSender_0_oldCommitment,
				balances_msgSender_1_oldCommitment,
			] = getInputCommitments(
				publicKey.hex(32),
				balances_msgSender_newCommitmentValue.integer,
				balances_msgSender_preimage
			);
		}

		while (balances_msgSender_commitmentFlag === false) {
			balances_msgSender_witness_0 = await getMembershipWitness(
				"ZKSenderShield",
				generalise(balances_msgSender_0_oldCommitment._id).integer
			);

			balances_msgSender_witness_1 = await getMembershipWitness(
				"ZKSenderShield",
				generalise(balances_msgSender_1_oldCommitment._id).integer
			);

			const tx = await joinCommitments(
				"ZKSenderShield",
				"balances",
				secretKey,
				publicKey,
				[11, balances_msgSender_stateVarId_key],
				[
					balances_msgSender_0_oldCommitment,
					balances_msgSender_1_oldCommitment,
				],
				[balances_msgSender_witness_0, balances_msgSender_witness_1],
				instance,
				contractAddr,
				web3
			);

			balances_msgSender_preimage = await getCommitmentsById(
				balances_msgSender_stateVarId
			);

			[
				balances_msgSender_commitmentFlag,
				balances_msgSender_0_oldCommitment,
				balances_msgSender_1_oldCommitment,
			] = getInputCommitments(
				publicKey.hex(32),
				balances_msgSender_newCommitmentValue.integer,
				balances_msgSender_preimage
			);
		}
		const balances_msgSender_0_prevSalt = generalise(
			balances_msgSender_0_oldCommitment.preimage.salt
		);
		const balances_msgSender_1_prevSalt = generalise(
			balances_msgSender_1_oldCommitment.preimage.salt
		);
		const balances_msgSender_0_prev = generalise(
			balances_msgSender_0_oldCommitment.preimage.value
		);
		const balances_msgSender_1_prev = generalise(
			balances_msgSender_1_oldCommitment.preimage.value
		);

		// Extract set membership witness:

		// generate witness for partitioned state
		balances_msgSender_witness_0 = await getMembershipWitness(
			"ZKSenderShield",
			generalise(balances_msgSender_0_oldCommitment._id).integer
		);
		balances_msgSender_witness_1 = await getMembershipWitness(
			"ZKSenderShield",
			generalise(balances_msgSender_1_oldCommitment._id).integer
		);
		const balances_msgSender_0_index = generalise(
			balances_msgSender_witness_0.index
		);
		const balances_msgSender_1_index = generalise(
			balances_msgSender_witness_1.index
		);
		const balances_msgSender_root = generalise(
			balances_msgSender_witness_0.root
		);
		const balances_msgSender_0_path = generalise(
			balances_msgSender_witness_0.path
		).all;
		const balances_msgSender_1_path = generalise(
			balances_msgSender_witness_1.path
		).all;

		// non-secret line would go here but has been filtered out

		// increment would go here but has been filtered out

		// non-secret line would go here but has been filtered out

		// non-secret line would go here but has been filtered out

		// Calculate nullifier(s):

		let balances_msgSender_0_nullifier = poseidonHash([
			BigInt(balances_msgSender_stateVarId),
			BigInt(secretKey.hex(32)),
			BigInt(balances_msgSender_0_prevSalt.hex(32)),
		]);
		let balances_msgSender_1_nullifier = poseidonHash([
			BigInt(balances_msgSender_stateVarId),
			BigInt(secretKey.hex(32)),
			BigInt(balances_msgSender_1_prevSalt.hex(32)),
		]);
		balances_msgSender_0_nullifier = generalise(
			balances_msgSender_0_nullifier.hex(32)
		); // truncate
		balances_msgSender_1_nullifier = generalise(
			balances_msgSender_1_nullifier.hex(32)
		); // truncate
		// Non-membership witness for Nullifier
		const balances_msgSender_0_nullifier_NonMembership_witness =
			getnullifierMembershipWitness(balances_msgSender_0_nullifier);
		const balances_msgSender_1_nullifier_NonMembership_witness =
			getnullifierMembershipWitness(balances_msgSender_1_nullifier);

		const balances_msgSender_nullifierRoot = generalise(
			balances_msgSender_0_nullifier_NonMembership_witness.root
		);
		const balances_msgSender_0_nullifier_path = generalise(
			balances_msgSender_0_nullifier_NonMembership_witness.path
		).all;
		const balances_msgSender_1_nullifier_path = generalise(
			balances_msgSender_1_nullifier_NonMembership_witness.path
		).all;

		await temporaryUpdateNullifier(balances_msgSender_0_nullifier);
		await temporaryUpdateNullifier(balances_msgSender_1_nullifier);

		// Get the new updated nullifier Paths
		const balances_msgSender_0_updated_nullifier_NonMembership_witness =
			getupdatedNullifierPaths(balances_msgSender_0_nullifier);
		const balances_msgSender_1_updated_nullifier_NonMembership_witness =
			getupdatedNullifierPaths(balances_msgSender_1_nullifier);

		const balances_msgSender_newNullifierRoot = generalise(
			balances_msgSender_0_updated_nullifier_NonMembership_witness.root
		);
		const balances_msgSender_0_nullifier_updatedpath = generalise(
			balances_msgSender_0_updated_nullifier_NonMembership_witness.path
		).all;
		const balances_msgSender_1_nullifier_updatedpath = generalise(
			balances_msgSender_1_updated_nullifier_NonMembership_witness.path
		).all;

		// Calculate commitment(s):

		const balances_msgSender_2_newSalt = generalise(utils.randomHex(31));

		let balances_msgSender_change =
			parseInt(balances_msgSender_0_prev.integer, 10) +
			parseInt(balances_msgSender_1_prev.integer, 10) -
			parseInt(balances_msgSender_newCommitmentValue.integer, 10);

		balances_msgSender_change = generalise(balances_msgSender_change);

		let balances_msgSender_2_newCommitment = poseidonHash([
			BigInt(balances_msgSender_stateVarId),
			BigInt(balances_msgSender_change.hex(32)),
			BigInt(publicKey.hex(32)),
			BigInt(balances_msgSender_2_newSalt.hex(32)),
		]);

		balances_msgSender_2_newCommitment = generalise(
			balances_msgSender_2_newCommitment.hex(32)
		); // truncate

		// Call Zokrates to generate the proof:

		const allInputs = [
			amountOut.integer,
			balances_msgSender_stateVarId_key.integer,
			secretKey.integer,
			secretKey.integer,
			balances_msgSender_nullifierRoot.integer,
			balances_msgSender_newNullifierRoot.integer,
			balances_msgSender_0_nullifier.integer,
			balances_msgSender_0_nullifier_path.integer,
			balances_msgSender_0_nullifier_updatedpath.integer,
			balances_msgSender_1_nullifier.integer,
			balances_msgSender_1_nullifier_path.integer,
			balances_msgSender_1_nullifier_updatedpath.integer,
			balances_msgSender_0_prev.integer,
			balances_msgSender_0_prevSalt.integer,
			balances_msgSender_1_prev.integer,
			balances_msgSender_1_prevSalt.integer,
			balances_msgSender_root.integer,
			balances_msgSender_0_index.integer,
			balances_msgSender_0_path.integer,
			balances_msgSender_1_index.integer,
			balances_msgSender_1_path.integer,
			balances_msgSender_newOwnerPublicKey.integer,
			balances_msgSender_2_newSalt.integer,
			balances_msgSender_2_newCommitment.integer,
		].flat(Infinity);
		const res = await generateProof("unVault", allInputs);
		const proof = generalise(Object.values(res.proof).flat(Infinity))
			.map((coeff) => coeff.integer)
			.flat(Infinity);

		let BackupData = [];

		// Encrypt pre-image for state variable balances_msgSender as a backup:

		let balances_msgSender_ephSecretKey = generalise(utils.randomHex(31));

		let balances_msgSender_ephPublicKeyPoint = generalise(
			scalarMult(
				balances_msgSender_ephSecretKey.hex(32),
				config.BABYJUBJUB.GENERATOR
			)
		);

		let balances_msgSender_ephPublicKey = compressStarlightKey(
			balances_msgSender_ephPublicKeyPoint
		);

		while (balances_msgSender_ephPublicKey === null) {
			balances_msgSender_ephSecretKey = generalise(utils.randomHex(31));

			balances_msgSender_ephPublicKeyPoint = generalise(
				scalarMult(
					balances_msgSender_ephSecretKey.hex(32),
					config.BABYJUBJUB.GENERATOR
				)
			);

			balances_msgSender_ephPublicKey = compressStarlightKey(
				balances_msgSender_ephPublicKeyPoint
			);
		}

		const balances_msgSender_bcipherText = encrypt(
			[
				BigInt(balances_msgSender_2_newSalt.hex(32)),
				BigInt(balances_msgSender_stateVarId_key.hex(32)),
				BigInt(generalise(balances_msgSender_stateVarIdInit).hex(32)),
				BigInt(balances_msgSender_change.hex(32)),
			],
			balances_msgSender_ephSecretKey.hex(32),
			[
				decompressStarlightKey(balances_msgSender_newOwnerPublicKey)[0].hex(32),
				decompressStarlightKey(balances_msgSender_newOwnerPublicKey)[1].hex(32),
			]
		);

		let balances_msgSender_cipherText_combined = {
			varName: "balances a",
			cipherText: balances_msgSender_bcipherText,
			ephPublicKey: balances_msgSender_ephPublicKey.hex(32),
		};

		BackupData.push(balances_msgSender_cipherText_combined);

		// Send transaction to the blockchain:

		const txData = await instance.methods
			.unVault(
				amountOut.integer,
				{
					customInputs: [1],
					nullifierRoot: balances_msgSender_nullifierRoot.integer,
					latestNullifierRoot: balances_msgSender_newNullifierRoot.integer,
					newNullifiers: [
						balances_msgSender_0_nullifier.integer,
						balances_msgSender_1_nullifier.integer,
					],
					commitmentRoot: balances_msgSender_root.integer,
					newCommitments: [balances_msgSender_2_newCommitment.integer],
					cipherText: [],
					encKeys: [],
				},
				proof,
				BackupData
			)
			.encodeABI();

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
			throw new Error(
				"Tx failed - the commitment was not accepted on-chain, or the contract is not deployed."
			);
		}

		let encEvent = "";

		try {
			encEvent = await instance.getPastEvents("EncryptedData");
		} catch (err) {
			console.log("No encrypted event");
		}

		let encBackupEvent = "";

		try {
			encBackupEvent = await instance.getPastEvents("EncryptedBackupData");
		} catch (err) {
			console.log("No encrypted backup event");
		}

		// Write new commitment preimage to db:

		await markNullified(
			generalise(balances_msgSender_0_oldCommitment._id),
			secretKey.hex(32)
		);

		await markNullified(
			generalise(balances_msgSender_1_oldCommitment._id),
			secretKey.hex(32)
		);

		await storeCommitment({
			hash: balances_msgSender_2_newCommitment,
			name: "balances",
			mappingKey: balances_msgSender_stateVarId_key.integer,
			preimage: {
				stateVarId: generalise(balances_msgSender_stateVarId),
				value: balances_msgSender_change,
				salt: balances_msgSender_2_newSalt,
				publicKey: balances_msgSender_newOwnerPublicKey,
			},
			secretKey:
				balances_msgSender_newOwnerPublicKey.integer === publicKey.integer
					? secretKey
					: null,
			isNullified: false,
		});

		return { tx, encEvent, encBackupEvent };
	}
}
