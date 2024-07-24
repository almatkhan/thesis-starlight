/* eslint-disable prettier/prettier, camelcase, prefer-const, no-unused-vars */
import config from "config";
import assert from "assert";

import { SendManager } from "./send.mjs";
import { VaultManager } from "./vault.mjs";
import { startEventFilter, getSiblingPath } from "./common/timber.mjs";
import fs from "fs";
import logger from "./common/logger.mjs";
import { decrypt } from "./common/number-theory.mjs";
import {
	getAllCommitments,
	getCommitmentsByState,
	reinstateNullifiers,
	getBalance,
	getSharedSecretskeys,
	getBalanceByState,
	addConstructorNullifiers,
} from "./common/commitment-storage.mjs";
import { backupDataRetriever } from "./BackupDataRetriever.mjs";
import web3 from "./common/web3.mjs";

/**
      NOTE: this is the api service file, if you need to call any function use the correct url and if Your input contract has two functions, add() and minus().
      minus() cannot be called before an initial add(). */

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let leafIndex;
let encryption = {};
// eslint-disable-next-line func-names

export class ServiceManager {
	constructor(web3) {
		this.web3 = web3;

		this.vault = new VaultManager(web3);
		this.send = new SendManager(web3);
	}
	async init() {
		await this.vault.init();
		await this.send.init();
	}

	// eslint-disable-next-line func-names
	async service_vault(req, res, next) {
		try {
			await startEventFilter("ZKSenderShield");
			const { amountIn } = req.body;
			const balances_msgSender_newOwnerPublicKey =
				req.body.balances_msgSender_newOwnerPublicKey || 0;
			const { tx, encEvent, encBackupEvent } = await this.vault.vault(
				amountIn,
				balances_msgSender_newOwnerPublicKey
			);
			// prints the tx
			console.log(tx);
			res.send({ tx, encEvent, encBackupEvent });
			// reassigns leafIndex to the index of the first commitment added by this function
			if (tx.event) {
				leafIndex = tx.returnValues[0];
				// prints the new leaves (commitments) added by this function call
				console.log(`Merkle tree event returnValues:`);
				console.log(tx.returnValues);
			}
			if (encEvent.event) {
				encryption.msgs = encEvent[0].returnValues[0];
				encryption.key = encEvent[0].returnValues[1];
				console.log("EncryptedMsgs:");
				console.log(encEvent[0].returnValues[0]);
			}
			await sleep(10);
		} catch (err) {
			logger.error(err);
			res.send({ errors: [err.message] });
		}
	}

	// eslint-disable-next-line func-names
	async service_send(req, res, next) {
		try {
			await startEventFilter("ZKSenderShield");
			const { recipient } = req.body;
			const { amount } = req.body;
			const balances_msgSender_newOwnerPublicKey =
				req.body.balances_msgSender_newOwnerPublicKey || 0;
			const balances_recipient_newOwnerPublicKey =
				req.body.balances_recipient_newOwnerPublicKey || 0;
			const { tx, encEvent, encBackupEvent } = await this.send.send(
				recipient,
				amount,
				balances_msgSender_newOwnerPublicKey,
				balances_recipient_newOwnerPublicKey
			);
			// prints the tx
			console.log(tx);
			res.send({ tx, encEvent, encBackupEvent });
			// reassigns leafIndex to the index of the first commitment added by this function
			if (tx.event) {
				leafIndex = tx.returnValues[0];
				// prints the new leaves (commitments) added by this function call
				console.log(`Merkle tree event returnValues:`);
				console.log(tx.returnValues);
			}
			if (encEvent.event) {
				encryption.msgs = encEvent[0].returnValues[0];
				encryption.key = encEvent[0].returnValues[1];
				console.log("EncryptedMsgs:");
				console.log(encEvent[0].returnValues[0]);
			}
			await sleep(10);
		} catch (err) {
			logger.error(err);
			res.send({ errors: [err.message] });
		}
	}
}

export async function service_allCommitments(req, res, next) {
	try {
		const commitments = await getAllCommitments();
		res.send({ commitments });
		await sleep(10);
	} catch (err) {
		logger.error(err);
		res.send({ errors: [err.message] });
	}
}
export async function service_getBalance(req, res, next) {
	try {
		const sum = await getBalance();
		res.send({ " Total Balance": sum });
	} catch (error) {
		console.error("Error in calculation :", error);
		res.status(500).send({ error: err.message });
	}
}

export async function service_getBalanceByState(req, res, next) {
	try {
		const { name, mappingKey } = req.body;
		const balance = await getBalanceByState(name, mappingKey);
		res.send({ " Total Balance": balance });
	} catch (error) {
		console.error("Error in calculation :", error);
		res.status(500).send({ error: err.message });
	}
}

export async function service_getCommitmentsByState(req, res, next) {
	try {
		const { name, mappingKey } = req.body;
		const commitments = await getCommitmentsByState(name, mappingKey);
		res.send({ commitments });
		await sleep(10);
	} catch (err) {
		logger.error(err);
		res.send({ errors: [err.message] });
	}
}

export async function service_reinstateNullifiers(req, res, next) {
	try {
		await reinstateNullifiers();
		res.send("Complete");
		await sleep(10);
	} catch (err) {
		logger.error(err);
		res.send({ errors: [err.message] });
	}
}

export async function service_backupData(req, res, next) {
	try {
		await backupDataRetriever();
		res.send("Complete");
		await sleep(10);
	} catch (err) {
		logger.error(err);
		res.send({ errors: [err.message] });
	}
}
export async function service_getSharedKeys(req, res, next) {
	try {
		const { recipientAddress } = req.body;
		const recipientPubKey = req.body.recipientPubKey || 0;
		const SharedKeys = await getSharedSecretskeys(
			recipientAddress,
			recipientPubKey
		);
		res.send({ SharedKeys });
		await sleep(10);
	} catch (err) {
		logger.error(err);
		res.send({ errors: [err.message] });
	}
}
