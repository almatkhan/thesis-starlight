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

export class InitSequenceNumberManager {
	constructor(web3) {
		this.web3 = web3;
	}

	async init() {
		this.instance = await getContractInstance("SyntheticPpaShield");
		this.contractAddr = await getContractAddress("SyntheticPpaShield");
	}

	async initSequenceNumber(
		_latestShortfallSequenceNumber_newOwnerPublicKey = 0
	) {
		const instance = this.instance;
		const contractAddr = this.contractAddr;
		const web3 = this.web3;

		const msgValue = 0;
		let latestShortfallSequenceNumber_newOwnerPublicKey = generalise(
			_latestShortfallSequenceNumber_newOwnerPublicKey
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

		const latestShortfallSequenceNumber_stateVarId = generalise(22).hex(32);

		let latestShortfallSequenceNumber_commitmentExists = true;
		let latestShortfallSequenceNumber_witnessRequired = true;

		const latestShortfallSequenceNumber_commitment =
			await getCurrentWholeCommitment(latestShortfallSequenceNumber_stateVarId);

		let latestShortfallSequenceNumber_preimage = {
			value: 0,
			salt: 0,
			commitment: 0,
		};
		if (!latestShortfallSequenceNumber_commitment) {
			latestShortfallSequenceNumber_commitmentExists = false;
			latestShortfallSequenceNumber_witnessRequired = false;
		} else {
			latestShortfallSequenceNumber_preimage =
				latestShortfallSequenceNumber_commitment.preimage;
		}

		// read preimage for whole state
		latestShortfallSequenceNumber_newOwnerPublicKey =
			_latestShortfallSequenceNumber_newOwnerPublicKey === 0
				? generalise(
						await instance.methods
							.zkpPublicKeys(await instance.methods.owner().call())
							.call()
				  )
				: latestShortfallSequenceNumber_newOwnerPublicKey;

		const latestShortfallSequenceNumber_currentCommitment =
			latestShortfallSequenceNumber_commitmentExists
				? generalise(latestShortfallSequenceNumber_commitment._id)
				: generalise(0);
		const latestShortfallSequenceNumber_prev = generalise(
			latestShortfallSequenceNumber_preimage.value
		);
		const latestShortfallSequenceNumber_prevSalt = generalise(
			latestShortfallSequenceNumber_preimage.salt
		);

		// Extract set membership witness:

		// generate witness for whole state
		const latestShortfallSequenceNumber_emptyPath = new Array(32).fill(0);
		const latestShortfallSequenceNumber_witness =
			latestShortfallSequenceNumber_witnessRequired
				? await getMembershipWitness(
						"SyntheticPpaShield",
						latestShortfallSequenceNumber_currentCommitment.integer
				  )
				: {
						index: 0,
						path: latestShortfallSequenceNumber_emptyPath,
						root: (await getRoot("SyntheticPpaShield")) || 0,
				  };
		const latestShortfallSequenceNumber_index = generalise(
			latestShortfallSequenceNumber_witness.index
		);
		const latestShortfallSequenceNumber_root = generalise(
			latestShortfallSequenceNumber_witness.root
		);
		const latestShortfallSequenceNumber_path = generalise(
			latestShortfallSequenceNumber_witness.path
		).all;

		// non-secret line would go here but has been filtered out

		let latestShortfallSequenceNumber = generalise(0);

		// Calculate nullifier(s):

		let latestShortfallSequenceNumber_nullifier =
			latestShortfallSequenceNumber_commitmentExists
				? poseidonHash([
						BigInt(latestShortfallSequenceNumber_stateVarId),
						BigInt(secretKey.hex(32)),
						BigInt(latestShortfallSequenceNumber_prevSalt.hex(32)),
				  ])
				: poseidonHash([
						BigInt(latestShortfallSequenceNumber_stateVarId),
						BigInt(generalise(0).hex(32)),
						BigInt(latestShortfallSequenceNumber_prevSalt.hex(32)),
				  ]);

		latestShortfallSequenceNumber_nullifier = generalise(
			latestShortfallSequenceNumber_nullifier.hex(32)
		); // truncate
		// Non-membership witness for Nullifier
		const latestShortfallSequenceNumber_nullifier_NonMembership_witness =
			getnullifierMembershipWitness(latestShortfallSequenceNumber_nullifier);

		const latestShortfallSequenceNumber_nullifierRoot = generalise(
			latestShortfallSequenceNumber_nullifier_NonMembership_witness.root
		);
		const latestShortfallSequenceNumber_nullifier_path = generalise(
			latestShortfallSequenceNumber_nullifier_NonMembership_witness.path
		).all;

		await temporaryUpdateNullifier(latestShortfallSequenceNumber_nullifier);

		// Get the new updated nullifier Paths
		const latestShortfallSequenceNumber_updated_nullifier_NonMembership_witness =
			getupdatedNullifierPaths(latestShortfallSequenceNumber_nullifier);
		const latestShortfallSequenceNumber_nullifier_updatedpath = generalise(
			latestShortfallSequenceNumber_updated_nullifier_NonMembership_witness.path
		).all;
		const latestShortfallSequenceNumber_newNullifierRoot = generalise(
			latestShortfallSequenceNumber_updated_nullifier_NonMembership_witness.root
		);

		// Calculate commitment(s):

		const latestShortfallSequenceNumber_newSalt = generalise(
			utils.randomHex(31)
		);

		let latestShortfallSequenceNumber_newCommitment = poseidonHash([
			BigInt(latestShortfallSequenceNumber_stateVarId),
			BigInt(latestShortfallSequenceNumber.hex(32)),
			BigInt(latestShortfallSequenceNumber_newOwnerPublicKey.hex(32)),
			BigInt(latestShortfallSequenceNumber_newSalt.hex(32)),
		]);

		latestShortfallSequenceNumber_newCommitment = generalise(
			latestShortfallSequenceNumber_newCommitment.hex(32)
		); // truncate

		// Call Zokrates to generate the proof:

		const allInputs = [
			latestShortfallSequenceNumber_commitmentExists
				? secretKey.integer
				: generalise(0).integer,
			latestShortfallSequenceNumber_nullifierRoot.integer,
			latestShortfallSequenceNumber_newNullifierRoot.integer,
			latestShortfallSequenceNumber_nullifier.integer,
			latestShortfallSequenceNumber_nullifier_path.integer,
			latestShortfallSequenceNumber_nullifier_updatedpath.integer,
			latestShortfallSequenceNumber_prev.integer,
			latestShortfallSequenceNumber_prevSalt.integer,
			latestShortfallSequenceNumber_commitmentExists ? 0 : 1,
			latestShortfallSequenceNumber_root.integer,
			latestShortfallSequenceNumber_index.integer,
			latestShortfallSequenceNumber_path.integer,
			latestShortfallSequenceNumber_newOwnerPublicKey.integer,
			latestShortfallSequenceNumber_newSalt.integer,
			latestShortfallSequenceNumber_newCommitment.integer,
		].flat(Infinity);
		const res = await generateProof("initSequenceNumber", allInputs);
		const proof = generalise(Object.values(res.proof).flat(Infinity))
			.map((coeff) => coeff.integer)
			.flat(Infinity);

		let BackupData = [];

		// Encrypt pre-image for state variable latestShortfallSequenceNumber as a backup:

		let latestShortfallSequenceNumber_ephSecretKey = generalise(
			utils.randomHex(31)
		);

		let latestShortfallSequenceNumber_ephPublicKeyPoint = generalise(
			scalarMult(
				latestShortfallSequenceNumber_ephSecretKey.hex(32),
				config.BABYJUBJUB.GENERATOR
			)
		);

		let latestShortfallSequenceNumber_ephPublicKey = compressStarlightKey(
			latestShortfallSequenceNumber_ephPublicKeyPoint
		);

		while (latestShortfallSequenceNumber_ephPublicKey === null) {
			latestShortfallSequenceNumber_ephSecretKey = generalise(
				utils.randomHex(31)
			);

			latestShortfallSequenceNumber_ephPublicKeyPoint = generalise(
				scalarMult(
					latestShortfallSequenceNumber_ephSecretKey.hex(32),
					config.BABYJUBJUB.GENERATOR
				)
			);

			latestShortfallSequenceNumber_ephPublicKey = compressStarlightKey(
				latestShortfallSequenceNumber_ephPublicKeyPoint
			);
		}

		const latestShortfallSequenceNumber_bcipherText = encrypt(
			[
				BigInt(latestShortfallSequenceNumber_newSalt.hex(32)),
				BigInt(latestShortfallSequenceNumber_stateVarId),
				BigInt(latestShortfallSequenceNumber.hex(32)),
			],
			latestShortfallSequenceNumber_ephSecretKey.hex(32),
			[
				decompressStarlightKey(
					latestShortfallSequenceNumber_newOwnerPublicKey
				)[0].hex(32),
				decompressStarlightKey(
					latestShortfallSequenceNumber_newOwnerPublicKey
				)[1].hex(32),
			]
		);

		let latestShortfallSequenceNumber_cipherText_combined = {
			varName: "latestShortfallSequenceNumber",
			cipherText: latestShortfallSequenceNumber_bcipherText,
			ephPublicKey: latestShortfallSequenceNumber_ephPublicKey.hex(32),
		};

		BackupData.push(latestShortfallSequenceNumber_cipherText_combined);

		// Send transaction to the blockchain:

		const txData = await instance.methods
			.initSequenceNumber(
				{
					customInputs: [1],
					nullifierRoot: latestShortfallSequenceNumber_nullifierRoot.integer,
					latestNullifierRoot:
						latestShortfallSequenceNumber_newNullifierRoot.integer,
					newNullifiers: [latestShortfallSequenceNumber_nullifier.integer],
					commitmentRoot: latestShortfallSequenceNumber_root.integer,
					newCommitments: [latestShortfallSequenceNumber_newCommitment.integer],
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

		if (latestShortfallSequenceNumber_commitmentExists)
			await markNullified(
				latestShortfallSequenceNumber_currentCommitment,
				secretKey.hex(32)
			);
		else await updateNullifierTree(); // Else we always update it in markNullified

		await storeCommitment({
			hash: latestShortfallSequenceNumber_newCommitment,
			name: "latestShortfallSequenceNumber",
			mappingKey: null,
			preimage: {
				stateVarId: generalise(latestShortfallSequenceNumber_stateVarId),
				value: latestShortfallSequenceNumber,
				salt: latestShortfallSequenceNumber_newSalt,
				publicKey: latestShortfallSequenceNumber_newOwnerPublicKey,
			},
			secretKey:
				latestShortfallSequenceNumber_newOwnerPublicKey.integer ===
				publicKey.integer
					? secretKey
					: null,
			isNullified: false,
		});

		return { tx, encEvent, encBackupEvent };
	}
}
