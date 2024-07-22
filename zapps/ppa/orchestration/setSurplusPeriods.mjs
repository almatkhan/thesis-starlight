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

export class SetSurplusPeriodsManager {
	constructor(web3) {
		this.web3 = web3;
	}

	async init() {
		this.instance = await getContractInstance("SyntheticPpaShield");
		this.contractAddr = await getContractAddress("SyntheticPpaShield");
	}

	async setSurplusPeriods(
		_surplusPeriods,
		_numberOfConsecutivePeriodsForSurplus_newOwnerPublicKey = 0
	) {
		const instance = this.instance;
		const contractAddr = this.contractAddr;
		const web3 = this.web3;

		const msgValue = 0;
		const surplusPeriods = generalise(_surplusPeriods);
		let numberOfConsecutivePeriodsForSurplus_newOwnerPublicKey = generalise(
			_numberOfConsecutivePeriodsForSurplus_newOwnerPublicKey
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

		const numberOfConsecutivePeriodsForSurplus_stateVarId =
			generalise(72).hex(32);

		let numberOfConsecutivePeriodsForSurplus_commitmentExists = true;
		let numberOfConsecutivePeriodsForSurplus_witnessRequired = true;

		const numberOfConsecutivePeriodsForSurplus_commitment =
			await getCurrentWholeCommitment(
				numberOfConsecutivePeriodsForSurplus_stateVarId
			);

		let numberOfConsecutivePeriodsForSurplus_preimage = {
			value: 0,
			salt: 0,
			commitment: 0,
		};
		if (!numberOfConsecutivePeriodsForSurplus_commitment) {
			numberOfConsecutivePeriodsForSurplus_commitmentExists = false;
			numberOfConsecutivePeriodsForSurplus_witnessRequired = false;
		} else {
			numberOfConsecutivePeriodsForSurplus_preimage =
				numberOfConsecutivePeriodsForSurplus_commitment.preimage;
		}

		// read preimage for whole state
		numberOfConsecutivePeriodsForSurplus_newOwnerPublicKey =
			_numberOfConsecutivePeriodsForSurplus_newOwnerPublicKey === 0
				? generalise(
						await instance.methods
							.zkpPublicKeys(await instance.methods.owner().call())
							.call()
				  )
				: numberOfConsecutivePeriodsForSurplus_newOwnerPublicKey;

		const numberOfConsecutivePeriodsForSurplus_currentCommitment =
			numberOfConsecutivePeriodsForSurplus_commitmentExists
				? generalise(numberOfConsecutivePeriodsForSurplus_commitment._id)
				: generalise(0);
		const numberOfConsecutivePeriodsForSurplus_prev = generalise(
			numberOfConsecutivePeriodsForSurplus_preimage.value
		);
		const numberOfConsecutivePeriodsForSurplus_prevSalt = generalise(
			numberOfConsecutivePeriodsForSurplus_preimage.salt
		);

		// Extract set membership witness:

		// generate witness for whole state
		const numberOfConsecutivePeriodsForSurplus_emptyPath = new Array(32).fill(
			0
		);
		const numberOfConsecutivePeriodsForSurplus_witness =
			numberOfConsecutivePeriodsForSurplus_witnessRequired
				? await getMembershipWitness(
						"SyntheticPpaShield",
						numberOfConsecutivePeriodsForSurplus_currentCommitment.integer
				  )
				: {
						index: 0,
						path: numberOfConsecutivePeriodsForSurplus_emptyPath,
						root: (await getRoot("SyntheticPpaShield")) || 0,
				  };
		const numberOfConsecutivePeriodsForSurplus_index = generalise(
			numberOfConsecutivePeriodsForSurplus_witness.index
		);
		const numberOfConsecutivePeriodsForSurplus_root = generalise(
			numberOfConsecutivePeriodsForSurplus_witness.root
		);
		const numberOfConsecutivePeriodsForSurplus_path = generalise(
			numberOfConsecutivePeriodsForSurplus_witness.path
		).all;

		// non-secret line would go here but has been filtered out

		let numberOfConsecutivePeriodsForSurplus = generalise(
			parseInt(surplusPeriods.integer, 10)
		);

		// Calculate nullifier(s):

		let numberOfConsecutivePeriodsForSurplus_nullifier =
			numberOfConsecutivePeriodsForSurplus_commitmentExists
				? poseidonHash([
						BigInt(numberOfConsecutivePeriodsForSurplus_stateVarId),
						BigInt(secretKey.hex(32)),
						BigInt(numberOfConsecutivePeriodsForSurplus_prevSalt.hex(32)),
				  ])
				: poseidonHash([
						BigInt(numberOfConsecutivePeriodsForSurplus_stateVarId),
						BigInt(generalise(0).hex(32)),
						BigInt(numberOfConsecutivePeriodsForSurplus_prevSalt.hex(32)),
				  ]);

		numberOfConsecutivePeriodsForSurplus_nullifier = generalise(
			numberOfConsecutivePeriodsForSurplus_nullifier.hex(32)
		); // truncate
		// Non-membership witness for Nullifier
		const numberOfConsecutivePeriodsForSurplus_nullifier_NonMembership_witness =
			getnullifierMembershipWitness(
				numberOfConsecutivePeriodsForSurplus_nullifier
			);

		const numberOfConsecutivePeriodsForSurplus_nullifierRoot = generalise(
			numberOfConsecutivePeriodsForSurplus_nullifier_NonMembership_witness.root
		);
		const numberOfConsecutivePeriodsForSurplus_nullifier_path = generalise(
			numberOfConsecutivePeriodsForSurplus_nullifier_NonMembership_witness.path
		).all;

		await temporaryUpdateNullifier(
			numberOfConsecutivePeriodsForSurplus_nullifier
		);

		// Get the new updated nullifier Paths
		const numberOfConsecutivePeriodsForSurplus_updated_nullifier_NonMembership_witness =
			getupdatedNullifierPaths(numberOfConsecutivePeriodsForSurplus_nullifier);
		const numberOfConsecutivePeriodsForSurplus_nullifier_updatedpath =
			generalise(
				numberOfConsecutivePeriodsForSurplus_updated_nullifier_NonMembership_witness.path
			).all;
		const numberOfConsecutivePeriodsForSurplus_newNullifierRoot = generalise(
			numberOfConsecutivePeriodsForSurplus_updated_nullifier_NonMembership_witness.root
		);

		// Calculate commitment(s):

		const numberOfConsecutivePeriodsForSurplus_newSalt = generalise(
			utils.randomHex(31)
		);

		let numberOfConsecutivePeriodsForSurplus_newCommitment = poseidonHash([
			BigInt(numberOfConsecutivePeriodsForSurplus_stateVarId),
			BigInt(numberOfConsecutivePeriodsForSurplus.hex(32)),
			BigInt(numberOfConsecutivePeriodsForSurplus_newOwnerPublicKey.hex(32)),
			BigInt(numberOfConsecutivePeriodsForSurplus_newSalt.hex(32)),
		]);

		numberOfConsecutivePeriodsForSurplus_newCommitment = generalise(
			numberOfConsecutivePeriodsForSurplus_newCommitment.hex(32)
		); // truncate

		// Call Zokrates to generate the proof:

		const allInputs = [
			surplusPeriods.integer,
			numberOfConsecutivePeriodsForSurplus_commitmentExists
				? secretKey.integer
				: generalise(0).integer,
			numberOfConsecutivePeriodsForSurplus_nullifierRoot.integer,
			numberOfConsecutivePeriodsForSurplus_newNullifierRoot.integer,
			numberOfConsecutivePeriodsForSurplus_nullifier.integer,
			numberOfConsecutivePeriodsForSurplus_nullifier_path.integer,
			numberOfConsecutivePeriodsForSurplus_nullifier_updatedpath.integer,
			numberOfConsecutivePeriodsForSurplus_prev.integer,
			numberOfConsecutivePeriodsForSurplus_prevSalt.integer,
			numberOfConsecutivePeriodsForSurplus_commitmentExists ? 0 : 1,
			numberOfConsecutivePeriodsForSurplus_root.integer,
			numberOfConsecutivePeriodsForSurplus_index.integer,
			numberOfConsecutivePeriodsForSurplus_path.integer,
			numberOfConsecutivePeriodsForSurplus_newOwnerPublicKey.integer,
			numberOfConsecutivePeriodsForSurplus_newSalt.integer,
			numberOfConsecutivePeriodsForSurplus_newCommitment.integer,
		].flat(Infinity);
		const res = await generateProof("setSurplusPeriods", allInputs);
		const proof = generalise(Object.values(res.proof).flat(Infinity))
			.map((coeff) => coeff.integer)
			.flat(Infinity);

		let BackupData = [];

		// Encrypt pre-image for state variable numberOfConsecutivePeriodsForSurplus as a backup:

		let numberOfConsecutivePeriodsForSurplus_ephSecretKey = generalise(
			utils.randomHex(31)
		);

		let numberOfConsecutivePeriodsForSurplus_ephPublicKeyPoint = generalise(
			scalarMult(
				numberOfConsecutivePeriodsForSurplus_ephSecretKey.hex(32),
				config.BABYJUBJUB.GENERATOR
			)
		);

		let numberOfConsecutivePeriodsForSurplus_ephPublicKey =
			compressStarlightKey(
				numberOfConsecutivePeriodsForSurplus_ephPublicKeyPoint
			);

		while (numberOfConsecutivePeriodsForSurplus_ephPublicKey === null) {
			numberOfConsecutivePeriodsForSurplus_ephSecretKey = generalise(
				utils.randomHex(31)
			);

			numberOfConsecutivePeriodsForSurplus_ephPublicKeyPoint = generalise(
				scalarMult(
					numberOfConsecutivePeriodsForSurplus_ephSecretKey.hex(32),
					config.BABYJUBJUB.GENERATOR
				)
			);

			numberOfConsecutivePeriodsForSurplus_ephPublicKey = compressStarlightKey(
				numberOfConsecutivePeriodsForSurplus_ephPublicKeyPoint
			);
		}

		const numberOfConsecutivePeriodsForSurplus_bcipherText = encrypt(
			[
				BigInt(numberOfConsecutivePeriodsForSurplus_newSalt.hex(32)),
				BigInt(numberOfConsecutivePeriodsForSurplus_stateVarId),
				BigInt(numberOfConsecutivePeriodsForSurplus.hex(32)),
			],
			numberOfConsecutivePeriodsForSurplus_ephSecretKey.hex(32),
			[
				decompressStarlightKey(
					numberOfConsecutivePeriodsForSurplus_newOwnerPublicKey
				)[0].hex(32),
				decompressStarlightKey(
					numberOfConsecutivePeriodsForSurplus_newOwnerPublicKey
				)[1].hex(32),
			]
		);

		let numberOfConsecutivePeriodsForSurplus_cipherText_combined = {
			varName: "numberOfConsecutivePeriodsForSurplus",
			cipherText: numberOfConsecutivePeriodsForSurplus_bcipherText,
			ephPublicKey: numberOfConsecutivePeriodsForSurplus_ephPublicKey.hex(32),
		};

		BackupData.push(numberOfConsecutivePeriodsForSurplus_cipherText_combined);

		// Send transaction to the blockchain:

		const txData = await instance.methods
			.setSurplusPeriods(
				{
					customInputs: [1],
					nullifierRoot:
						numberOfConsecutivePeriodsForSurplus_nullifierRoot.integer,
					latestNullifierRoot:
						numberOfConsecutivePeriodsForSurplus_newNullifierRoot.integer,
					newNullifiers: [
						numberOfConsecutivePeriodsForSurplus_nullifier.integer,
					],
					commitmentRoot: numberOfConsecutivePeriodsForSurplus_root.integer,
					newCommitments: [
						numberOfConsecutivePeriodsForSurplus_newCommitment.integer,
					],
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

		if (numberOfConsecutivePeriodsForSurplus_commitmentExists)
			await markNullified(
				numberOfConsecutivePeriodsForSurplus_currentCommitment,
				secretKey.hex(32)
			);
		else await updateNullifierTree(); // Else we always update it in markNullified

		await storeCommitment({
			hash: numberOfConsecutivePeriodsForSurplus_newCommitment,
			name: "numberOfConsecutivePeriodsForSurplus",
			mappingKey: null,
			preimage: {
				stateVarId: generalise(numberOfConsecutivePeriodsForSurplus_stateVarId),
				value: numberOfConsecutivePeriodsForSurplus,
				salt: numberOfConsecutivePeriodsForSurplus_newSalt,
				publicKey: numberOfConsecutivePeriodsForSurplus_newOwnerPublicKey,
			},
			secretKey:
				numberOfConsecutivePeriodsForSurplus_newOwnerPublicKey.integer ===
				publicKey.integer
					? secretKey
					: null,
			isNullified: false,
		});

		return { tx, encEvent, encBackupEvent };
	}
}
