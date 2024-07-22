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

export class SetSequenceNumberIntervalManager {
	constructor(web3) {
		this.web3 = web3;
	}

	async init() {
		this.instance = await getContractInstance("SyntheticPpaShield");
		this.contractAddr = await getContractAddress("SyntheticPpaShield");
	}

	async setSequenceNumberInterval(
		_sequenceNumberIntervalParam,
		_sequenceNumberInterval_newOwnerPublicKey = 0
	) {
		const instance = this.instance;
		const contractAddr = this.contractAddr;
		const web3 = this.web3;

		const msgValue = 0;
		const sequenceNumberIntervalParam = generalise(
			_sequenceNumberIntervalParam
		);
		let sequenceNumberInterval_newOwnerPublicKey = generalise(
			_sequenceNumberInterval_newOwnerPublicKey
		);

		// Read dbs for keys and previous commitment values:

		if (!fs.existsSync(keyDb))
			await registerKey(utils.randomHex(31), "SyntheticPpaShield", true);
		const keys = JSON.parse(
			fs.readFileSync(keyDb, "utf-8", (err) => {
				console.log(err);
			})
		);
		const secretKey = generalise(keys.secretKey);
		const publicKey = generalise(keys.publicKey);

		// Initialise commitment preimage of whole state:

		const sequenceNumberInterval_stateVarId = generalise(31).hex(32);

		let sequenceNumberInterval_commitmentExists = true;
		let sequenceNumberInterval_witnessRequired = true;

		const sequenceNumberInterval_commitment = await getCurrentWholeCommitment(
			sequenceNumberInterval_stateVarId
		);

		let sequenceNumberInterval_preimage = {
			value: 0,
			salt: 0,
			commitment: 0,
		};
		if (!sequenceNumberInterval_commitment) {
			sequenceNumberInterval_commitmentExists = false;
			sequenceNumberInterval_witnessRequired = false;
		} else {
			sequenceNumberInterval_preimage =
				sequenceNumberInterval_commitment.preimage;
		}

		// read preimage for whole state
		sequenceNumberInterval_newOwnerPublicKey =
			_sequenceNumberInterval_newOwnerPublicKey === 0
				? generalise(
						await instance.methods
							.zkpPublicKeys(await instance.methods.owner().call())
							.call()
				  )
				: sequenceNumberInterval_newOwnerPublicKey;

		const sequenceNumberInterval_currentCommitment =
			sequenceNumberInterval_commitmentExists
				? generalise(sequenceNumberInterval_commitment._id)
				: generalise(0);
		const sequenceNumberInterval_prev = generalise(
			sequenceNumberInterval_preimage.value
		);
		const sequenceNumberInterval_prevSalt = generalise(
			sequenceNumberInterval_preimage.salt
		);

		// Extract set membership witness:

		// generate witness for whole state
		const sequenceNumberInterval_emptyPath = new Array(32).fill(0);
		const sequenceNumberInterval_witness =
			sequenceNumberInterval_witnessRequired
				? await getMembershipWitness(
						"SyntheticPpaShield",
						sequenceNumberInterval_currentCommitment.integer
				  )
				: {
						index: 0,
						path: sequenceNumberInterval_emptyPath,
						root: (await getRoot("SyntheticPpaShield")) || 0,
				  };
		const sequenceNumberInterval_index = generalise(
			sequenceNumberInterval_witness.index
		);
		const sequenceNumberInterval_root = generalise(
			sequenceNumberInterval_witness.root
		);
		const sequenceNumberInterval_path = generalise(
			sequenceNumberInterval_witness.path
		).all;

		// non-secret line would go here but has been filtered out

		let sequenceNumberInterval = generalise(
			parseInt(sequenceNumberIntervalParam.integer, 10)
		);

		// Calculate nullifier(s):

		let sequenceNumberInterval_nullifier =
			sequenceNumberInterval_commitmentExists
				? poseidonHash([
						BigInt(sequenceNumberInterval_stateVarId),
						BigInt(secretKey.hex(32)),
						BigInt(sequenceNumberInterval_prevSalt.hex(32)),
				  ])
				: poseidonHash([
						BigInt(sequenceNumberInterval_stateVarId),
						BigInt(generalise(0).hex(32)),
						BigInt(sequenceNumberInterval_prevSalt.hex(32)),
				  ]);

		sequenceNumberInterval_nullifier = generalise(
			sequenceNumberInterval_nullifier.hex(32)
		); // truncate
		// Non-membership witness for Nullifier
		const sequenceNumberInterval_nullifier_NonMembership_witness =
			getnullifierMembershipWitness(sequenceNumberInterval_nullifier);

		const sequenceNumberInterval_nullifierRoot = generalise(
			sequenceNumberInterval_nullifier_NonMembership_witness.root
		);
		const sequenceNumberInterval_nullifier_path = generalise(
			sequenceNumberInterval_nullifier_NonMembership_witness.path
		).all;

		await temporaryUpdateNullifier(sequenceNumberInterval_nullifier);

		// Get the new updated nullifier Paths
		const sequenceNumberInterval_updated_nullifier_NonMembership_witness =
			getupdatedNullifierPaths(sequenceNumberInterval_nullifier);
		const sequenceNumberInterval_nullifier_updatedpath = generalise(
			sequenceNumberInterval_updated_nullifier_NonMembership_witness.path
		).all;
		const sequenceNumberInterval_newNullifierRoot = generalise(
			sequenceNumberInterval_updated_nullifier_NonMembership_witness.root
		);

		// Calculate commitment(s):

		const sequenceNumberInterval_newSalt = generalise(utils.randomHex(31));

		let sequenceNumberInterval_newCommitment = poseidonHash([
			BigInt(sequenceNumberInterval_stateVarId),
			BigInt(sequenceNumberInterval.hex(32)),
			BigInt(sequenceNumberInterval_newOwnerPublicKey.hex(32)),
			BigInt(sequenceNumberInterval_newSalt.hex(32)),
		]);

		sequenceNumberInterval_newCommitment = generalise(
			sequenceNumberInterval_newCommitment.hex(32)
		); // truncate

		// Call Zokrates to generate the proof:

		const allInputs = [
			sequenceNumberIntervalParam.integer,
			sequenceNumberInterval_commitmentExists
				? secretKey.integer
				: generalise(0).integer,
			sequenceNumberInterval_nullifierRoot.integer,
			sequenceNumberInterval_newNullifierRoot.integer,
			sequenceNumberInterval_nullifier.integer,
			sequenceNumberInterval_nullifier_path.integer,
			sequenceNumberInterval_nullifier_updatedpath.integer,
			sequenceNumberInterval_prev.integer,
			sequenceNumberInterval_prevSalt.integer,
			sequenceNumberInterval_commitmentExists ? 0 : 1,
			sequenceNumberInterval_root.integer,
			sequenceNumberInterval_index.integer,
			sequenceNumberInterval_path.integer,
			sequenceNumberInterval_newOwnerPublicKey.integer,
			sequenceNumberInterval_newSalt.integer,
			sequenceNumberInterval_newCommitment.integer,
		].flat(Infinity);
		const res = await generateProof("setSequenceNumberInterval", allInputs);
		const proof = generalise(Object.values(res.proof).flat(Infinity))
			.map((coeff) => coeff.integer)
			.flat(Infinity);

		let BackupData = [];

		// Encrypt pre-image for state variable sequenceNumberInterval as a backup:

		let sequenceNumberInterval_ephSecretKey = generalise(utils.randomHex(31));

		let sequenceNumberInterval_ephPublicKeyPoint = generalise(
			scalarMult(
				sequenceNumberInterval_ephSecretKey.hex(32),
				config.BABYJUBJUB.GENERATOR
			)
		);

		let sequenceNumberInterval_ephPublicKey = compressStarlightKey(
			sequenceNumberInterval_ephPublicKeyPoint
		);

		while (sequenceNumberInterval_ephPublicKey === null) {
			sequenceNumberInterval_ephSecretKey = generalise(utils.randomHex(31));

			sequenceNumberInterval_ephPublicKeyPoint = generalise(
				scalarMult(
					sequenceNumberInterval_ephSecretKey.hex(32),
					config.BABYJUBJUB.GENERATOR
				)
			);

			sequenceNumberInterval_ephPublicKey = compressStarlightKey(
				sequenceNumberInterval_ephPublicKeyPoint
			);
		}

		const sequenceNumberInterval_bcipherText = encrypt(
			[
				BigInt(sequenceNumberInterval_newSalt.hex(32)),
				BigInt(sequenceNumberInterval_stateVarId),
				BigInt(sequenceNumberInterval.hex(32)),
			],
			sequenceNumberInterval_ephSecretKey.hex(32),
			[
				decompressStarlightKey(sequenceNumberInterval_newOwnerPublicKey)[0].hex(
					32
				),
				decompressStarlightKey(sequenceNumberInterval_newOwnerPublicKey)[1].hex(
					32
				),
			]
		);

		let sequenceNumberInterval_cipherText_combined = {
			varName: "sequenceNumberInterval",
			cipherText: sequenceNumberInterval_bcipherText,
			ephPublicKey: sequenceNumberInterval_ephPublicKey.hex(32),
		};

		BackupData.push(sequenceNumberInterval_cipherText_combined);

		// Send transaction to the blockchain:

		const txData = await instance.methods
			.setSequenceNumberInterval(
				{
					customInputs: [1],
					nullifierRoot: sequenceNumberInterval_nullifierRoot.integer,
					latestNullifierRoot: sequenceNumberInterval_newNullifierRoot.integer,
					newNullifiers: [sequenceNumberInterval_nullifier.integer],
					commitmentRoot: sequenceNumberInterval_root.integer,
					newCommitments: [sequenceNumberInterval_newCommitment.integer],
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

		if (sequenceNumberInterval_commitmentExists)
			await markNullified(
				sequenceNumberInterval_currentCommitment,
				secretKey.hex(32)
			);
		else await updateNullifierTree(); // Else we always update it in markNullified

		await storeCommitment({
			hash: sequenceNumberInterval_newCommitment,
			name: "sequenceNumberInterval",
			mappingKey: null,
			preimage: {
				stateVarId: generalise(sequenceNumberInterval_stateVarId),
				value: sequenceNumberInterval,
				salt: sequenceNumberInterval_newSalt,
				publicKey: sequenceNumberInterval_newOwnerPublicKey,
			},
			secretKey:
				sequenceNumberInterval_newOwnerPublicKey.integer === publicKey.integer
					? secretKey
					: null,
			isNullified: false,
		});

		return { tx, encEvent, encBackupEvent };
	}
}
