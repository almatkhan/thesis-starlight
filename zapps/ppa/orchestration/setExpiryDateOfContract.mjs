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

export class SetExpiryDateOfContractManager {
	constructor(web3) {
		this.web3 = web3;
	}

	async init() {
		this.instance = await getContractInstance("SyntheticPpaShield");
		this.contractAddr = await getContractAddress("SyntheticPpaShield");
	}

	async setExpiryDateOfContract(
		_expiryDateOfContractParam,
		_expiryDateOfContract_newOwnerPublicKey = 0
	) {
		const instance = this.instance;
		const contractAddr = this.contractAddr;
		const web3 = this.web3;

		const msgValue = 0;
		const expiryDateOfContractParam = generalise(_expiryDateOfContractParam);
		let expiryDateOfContract_newOwnerPublicKey = generalise(
			_expiryDateOfContract_newOwnerPublicKey
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

		const expiryDateOfContract_stateVarId = generalise(13).hex(32);

		let expiryDateOfContract_commitmentExists = true;
		let expiryDateOfContract_witnessRequired = true;

		const expiryDateOfContract_commitment = await getCurrentWholeCommitment(
			expiryDateOfContract_stateVarId
		);

		let expiryDateOfContract_preimage = {
			value: 0,
			salt: 0,
			commitment: 0,
		};
		if (!expiryDateOfContract_commitment) {
			expiryDateOfContract_commitmentExists = false;
			expiryDateOfContract_witnessRequired = false;
		} else {
			expiryDateOfContract_preimage = expiryDateOfContract_commitment.preimage;
		}

		// read preimage for whole state
		expiryDateOfContract_newOwnerPublicKey =
			_expiryDateOfContract_newOwnerPublicKey === 0
				? generalise(
						await instance.methods
							.zkpPublicKeys(await instance.methods.owner().call())
							.call()
				  )
				: expiryDateOfContract_newOwnerPublicKey;

		const expiryDateOfContract_currentCommitment =
			expiryDateOfContract_commitmentExists
				? generalise(expiryDateOfContract_commitment._id)
				: generalise(0);
		const expiryDateOfContract_prev = generalise(
			expiryDateOfContract_preimage.value
		);
		const expiryDateOfContract_prevSalt = generalise(
			expiryDateOfContract_preimage.salt
		);

		// Extract set membership witness:

		// generate witness for whole state
		const expiryDateOfContract_emptyPath = new Array(32).fill(0);
		const expiryDateOfContract_witness = expiryDateOfContract_witnessRequired
			? await getMembershipWitness(
					"SyntheticPpaShield",
					expiryDateOfContract_currentCommitment.integer
			  )
			: {
					index: 0,
					path: expiryDateOfContract_emptyPath,
					root: (await getRoot("SyntheticPpaShield")) || 0,
			  };
		const expiryDateOfContract_index = generalise(
			expiryDateOfContract_witness.index
		);
		const expiryDateOfContract_root = generalise(
			expiryDateOfContract_witness.root
		);
		const expiryDateOfContract_path = generalise(
			expiryDateOfContract_witness.path
		).all;

		// non-secret line would go here but has been filtered out

		let expiryDateOfContract = generalise(
			parseInt(expiryDateOfContractParam.integer, 10)
		);

		// Calculate nullifier(s):

		let expiryDateOfContract_nullifier = expiryDateOfContract_commitmentExists
			? poseidonHash([
					BigInt(expiryDateOfContract_stateVarId),
					BigInt(secretKey.hex(32)),
					BigInt(expiryDateOfContract_prevSalt.hex(32)),
			  ])
			: poseidonHash([
					BigInt(expiryDateOfContract_stateVarId),
					BigInt(generalise(0).hex(32)),
					BigInt(expiryDateOfContract_prevSalt.hex(32)),
			  ]);

		expiryDateOfContract_nullifier = generalise(
			expiryDateOfContract_nullifier.hex(32)
		); // truncate
		// Non-membership witness for Nullifier
		const expiryDateOfContract_nullifier_NonMembership_witness =
			getnullifierMembershipWitness(expiryDateOfContract_nullifier);

		const expiryDateOfContract_nullifierRoot = generalise(
			expiryDateOfContract_nullifier_NonMembership_witness.root
		);
		const expiryDateOfContract_nullifier_path = generalise(
			expiryDateOfContract_nullifier_NonMembership_witness.path
		).all;

		await temporaryUpdateNullifier(expiryDateOfContract_nullifier);

		// Get the new updated nullifier Paths
		const expiryDateOfContract_updated_nullifier_NonMembership_witness =
			getupdatedNullifierPaths(expiryDateOfContract_nullifier);
		const expiryDateOfContract_nullifier_updatedpath = generalise(
			expiryDateOfContract_updated_nullifier_NonMembership_witness.path
		).all;
		const expiryDateOfContract_newNullifierRoot = generalise(
			expiryDateOfContract_updated_nullifier_NonMembership_witness.root
		);

		// Calculate commitment(s):

		const expiryDateOfContract_newSalt = generalise(utils.randomHex(31));

		let expiryDateOfContract_newCommitment = poseidonHash([
			BigInt(expiryDateOfContract_stateVarId),
			BigInt(expiryDateOfContract.hex(32)),
			BigInt(expiryDateOfContract_newOwnerPublicKey.hex(32)),
			BigInt(expiryDateOfContract_newSalt.hex(32)),
		]);

		expiryDateOfContract_newCommitment = generalise(
			expiryDateOfContract_newCommitment.hex(32)
		); // truncate

		// Call Zokrates to generate the proof:

		const allInputs = [
			expiryDateOfContractParam.integer,
			expiryDateOfContract_commitmentExists
				? secretKey.integer
				: generalise(0).integer,
			expiryDateOfContract_nullifierRoot.integer,
			expiryDateOfContract_newNullifierRoot.integer,
			expiryDateOfContract_nullifier.integer,
			expiryDateOfContract_nullifier_path.integer,
			expiryDateOfContract_nullifier_updatedpath.integer,
			expiryDateOfContract_prev.integer,
			expiryDateOfContract_prevSalt.integer,
			expiryDateOfContract_commitmentExists ? 0 : 1,
			expiryDateOfContract_root.integer,
			expiryDateOfContract_index.integer,
			expiryDateOfContract_path.integer,
			expiryDateOfContract_newOwnerPublicKey.integer,
			expiryDateOfContract_newSalt.integer,
			expiryDateOfContract_newCommitment.integer,
		].flat(Infinity);
		const res = await generateProof("setExpiryDateOfContract", allInputs);
		const proof = generalise(Object.values(res.proof).flat(Infinity))
			.map((coeff) => coeff.integer)
			.flat(Infinity);

		let BackupData = [];

		// Encrypt pre-image for state variable expiryDateOfContract as a backup:

		let expiryDateOfContract_ephSecretKey = generalise(utils.randomHex(31));

		let expiryDateOfContract_ephPublicKeyPoint = generalise(
			scalarMult(
				expiryDateOfContract_ephSecretKey.hex(32),
				config.BABYJUBJUB.GENERATOR
			)
		);

		let expiryDateOfContract_ephPublicKey = compressStarlightKey(
			expiryDateOfContract_ephPublicKeyPoint
		);

		while (expiryDateOfContract_ephPublicKey === null) {
			expiryDateOfContract_ephSecretKey = generalise(utils.randomHex(31));

			expiryDateOfContract_ephPublicKeyPoint = generalise(
				scalarMult(
					expiryDateOfContract_ephSecretKey.hex(32),
					config.BABYJUBJUB.GENERATOR
				)
			);

			expiryDateOfContract_ephPublicKey = compressStarlightKey(
				expiryDateOfContract_ephPublicKeyPoint
			);
		}

		const expiryDateOfContract_bcipherText = encrypt(
			[
				BigInt(expiryDateOfContract_newSalt.hex(32)),
				BigInt(expiryDateOfContract_stateVarId),
				BigInt(expiryDateOfContract.hex(32)),
			],
			expiryDateOfContract_ephSecretKey.hex(32),
			[
				decompressStarlightKey(expiryDateOfContract_newOwnerPublicKey)[0].hex(
					32
				),
				decompressStarlightKey(expiryDateOfContract_newOwnerPublicKey)[1].hex(
					32
				),
			]
		);

		let expiryDateOfContract_cipherText_combined = {
			varName: "expiryDateOfContract",
			cipherText: expiryDateOfContract_bcipherText,
			ephPublicKey: expiryDateOfContract_ephPublicKey.hex(32),
		};

		BackupData.push(expiryDateOfContract_cipherText_combined);

		// Send transaction to the blockchain:

		const txData = await instance.methods
			.setExpiryDateOfContract(
				{
					customInputs: [1],
					nullifierRoot: expiryDateOfContract_nullifierRoot.integer,
					latestNullifierRoot: expiryDateOfContract_newNullifierRoot.integer,
					newNullifiers: [expiryDateOfContract_nullifier.integer],
					commitmentRoot: expiryDateOfContract_root.integer,
					newCommitments: [expiryDateOfContract_newCommitment.integer],
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

		if (expiryDateOfContract_commitmentExists)
			await markNullified(
				expiryDateOfContract_currentCommitment,
				secretKey.hex(32)
			);
		else await updateNullifierTree(); // Else we always update it in markNullified

		await storeCommitment({
			hash: expiryDateOfContract_newCommitment,
			name: "expiryDateOfContract",
			mappingKey: null,
			preimage: {
				stateVarId: generalise(expiryDateOfContract_stateVarId),
				value: expiryDateOfContract,
				salt: expiryDateOfContract_newSalt,
				publicKey: expiryDateOfContract_newOwnerPublicKey,
			},
			secretKey:
				expiryDateOfContract_newOwnerPublicKey.integer === publicKey.integer
					? secretKey
					: null,
			isNullified: false,
		});

		return { tx, encEvent, encBackupEvent };
	}
}
