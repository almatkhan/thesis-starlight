/* eslint-disable prettier/prettier, camelcase, prefer-const, no-unused-vars */
import config from "config";
import assert from "assert";

import { SetInitialContractParamsManager } from "./setInitialContractParams.mjs";
import { InitSurplusSequenceNumberManager } from "./initSurplusSequenceNumber.mjs";
import { InitSequenceNumberManager } from "./initSequenceNumber.mjs";
import { SetSequenceNumberIntervalManager } from "./setSequenceNumberInterval.mjs";
import { SetVolumeShareManager } from "./setVolumeShare.mjs";
import { SetExpiryDateOfContractManager } from "./setExpiryDateOfContract.mjs";
import { SetDailyInterestRateManager } from "./setDailyInterestRate.mjs";
import { SetSurplusPeriodsManager } from "./setSurplusPeriods.mjs";
import { SetSurplusThresholdManager } from "./setSurplusThreshold.mjs";
import { SetShortfallPeriodsManager } from "./setShortfallPeriods.mjs";
import { SetShortfallThresholdManager } from "./setShortfallThreshold.mjs";
import { SetBundlePriceManager } from "./setBundlePrice.mjs";
import { SetStrikePriceManager } from "./setStrikePrice.mjs";
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

		this.setStrikePrice = new SetStrikePriceManager(web3);
		this.setBundlePrice = new SetBundlePriceManager(web3);
		this.setShortfallThreshold = new SetShortfallThresholdManager(web3);
		this.setShortfallPeriods = new SetShortfallPeriodsManager(web3);
		this.setSurplusThreshold = new SetSurplusThresholdManager(web3);
		this.setSurplusPeriods = new SetSurplusPeriodsManager(web3);
		this.setDailyInterestRate = new SetDailyInterestRateManager(web3);
		this.setExpiryDateOfContract = new SetExpiryDateOfContractManager(web3);
		this.setVolumeShare = new SetVolumeShareManager(web3);
		this.setSequenceNumberInterval = new SetSequenceNumberIntervalManager(web3);
		this.initSequenceNumber = new InitSequenceNumberManager(web3);
		this.initSurplusSequenceNumber = new InitSurplusSequenceNumberManager(web3);
		this.setInitialContractParams = new SetInitialContractParamsManager(web3);
	}
	async init() {
		await this.setStrikePrice.init();
		await this.setBundlePrice.init();
		await this.setShortfallThreshold.init();
		await this.setShortfallPeriods.init();
		await this.setSurplusThreshold.init();
		await this.setSurplusPeriods.init();
		await this.setDailyInterestRate.init();
		await this.setExpiryDateOfContract.init();
		await this.setVolumeShare.init();
		await this.setSequenceNumberInterval.init();
		await this.initSequenceNumber.init();
		await this.initSurplusSequenceNumber.init();
		await this.setInitialContractParams.init();
	}

	// eslint-disable-next-line func-names
	async service_setStrikePrice(req, res, next) {
		try {
			await startEventFilter("SyntheticPpaShield");
			const { strikePriceParam } = req.body;
			const strikePrice_newOwnerPublicKey =
				req.body.strikePrice_newOwnerPublicKey || 0;
			const { tx, encEvent, encBackupEvent } =
				await this.setStrikePrice.setStrikePrice(
					strikePriceParam,
					strikePrice_newOwnerPublicKey
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
	async service_setBundlePrice(req, res, next) {
		try {
			await startEventFilter("SyntheticPpaShield");
			const { bundlePriceParam } = req.body;
			const bundlePrice_newOwnerPublicKey =
				req.body.bundlePrice_newOwnerPublicKey || 0;
			const { tx, encEvent, encBackupEvent } =
				await this.setBundlePrice.setBundlePrice(
					bundlePriceParam,
					bundlePrice_newOwnerPublicKey
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
	async service_setShortfallThreshold(req, res, next) {
		try {
			await startEventFilter("SyntheticPpaShield");
			const { shortfallThresholdParam } = req.body;
			const shortfallThreshold_newOwnerPublicKey =
				req.body.shortfallThreshold_newOwnerPublicKey || 0;
			const { tx, encEvent, encBackupEvent } =
				await this.setShortfallThreshold.setShortfallThreshold(
					shortfallThresholdParam,
					shortfallThreshold_newOwnerPublicKey
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
	async service_setShortfallPeriods(req, res, next) {
		try {
			await startEventFilter("SyntheticPpaShield");
			const { shortfallPeriods } = req.body;
			const numberOfConsecutivePeriodsForShortfall_newOwnerPublicKey =
				req.body.numberOfConsecutivePeriodsForShortfall_newOwnerPublicKey || 0;
			const { tx, encEvent, encBackupEvent } =
				await this.setShortfallPeriods.setShortfallPeriods(
					shortfallPeriods,
					numberOfConsecutivePeriodsForShortfall_newOwnerPublicKey
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
	async service_setSurplusThreshold(req, res, next) {
		try {
			await startEventFilter("SyntheticPpaShield");
			const { surplusThresholdParam } = req.body;
			const surplusThreshold_newOwnerPublicKey =
				req.body.surplusThreshold_newOwnerPublicKey || 0;
			const { tx, encEvent, encBackupEvent } =
				await this.setSurplusThreshold.setSurplusThreshold(
					surplusThresholdParam,
					surplusThreshold_newOwnerPublicKey
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
	async service_setSurplusPeriods(req, res, next) {
		try {
			await startEventFilter("SyntheticPpaShield");
			const { surplusPeriods } = req.body;
			const numberOfConsecutivePeriodsForSurplus_newOwnerPublicKey =
				req.body.numberOfConsecutivePeriodsForSurplus_newOwnerPublicKey || 0;
			const { tx, encEvent, encBackupEvent } =
				await this.setSurplusPeriods.setSurplusPeriods(
					surplusPeriods,
					numberOfConsecutivePeriodsForSurplus_newOwnerPublicKey
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
	async service_setDailyInterestRate(req, res, next) {
		try {
			await startEventFilter("SyntheticPpaShield");
			const { dailyInterestRateParam } = req.body;
			const dailyInterestRate_newOwnerPublicKey =
				req.body.dailyInterestRate_newOwnerPublicKey || 0;
			const { tx, encEvent, encBackupEvent } =
				await this.setDailyInterestRate.setDailyInterestRate(
					dailyInterestRateParam,
					dailyInterestRate_newOwnerPublicKey
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
	async service_setExpiryDateOfContract(req, res, next) {
		try {
			await startEventFilter("SyntheticPpaShield");
			const { expiryDateOfContractParam } = req.body;
			const expiryDateOfContract_newOwnerPublicKey =
				req.body.expiryDateOfContract_newOwnerPublicKey || 0;
			const { tx, encEvent, encBackupEvent } =
				await this.setExpiryDateOfContract.setExpiryDateOfContract(
					expiryDateOfContractParam,
					expiryDateOfContract_newOwnerPublicKey
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
	async service_setVolumeShare(req, res, next) {
		try {
			await startEventFilter("SyntheticPpaShield");
			const { volumeShareParam } = req.body;
			const volumeShare_newOwnerPublicKey =
				req.body.volumeShare_newOwnerPublicKey || 0;
			const { tx, encEvent, encBackupEvent } =
				await this.setVolumeShare.setVolumeShare(
					volumeShareParam,
					volumeShare_newOwnerPublicKey
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
	async service_setSequenceNumberInterval(req, res, next) {
		try {
			await startEventFilter("SyntheticPpaShield");
			const { sequenceNumberIntervalParam } = req.body;
			const sequenceNumberInterval_newOwnerPublicKey =
				req.body.sequenceNumberInterval_newOwnerPublicKey || 0;
			const { tx, encEvent, encBackupEvent } =
				await this.setSequenceNumberInterval.setSequenceNumberInterval(
					sequenceNumberIntervalParam,
					sequenceNumberInterval_newOwnerPublicKey
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
	async service_initSequenceNumber(req, res, next) {
		try {
			await startEventFilter("SyntheticPpaShield");
			const latestShortfallSequenceNumber_newOwnerPublicKey =
				req.body.latestShortfallSequenceNumber_newOwnerPublicKey || 0;
			const { tx, encEvent, encBackupEvent } =
				await this.initSequenceNumber.initSequenceNumber(
					latestShortfallSequenceNumber_newOwnerPublicKey
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
	async service_initSurplusSequenceNumber(req, res, next) {
		try {
			await startEventFilter("SyntheticPpaShield");
			const latestSurplusSequenceNumber_newOwnerPublicKey =
				req.body.latestSurplusSequenceNumber_newOwnerPublicKey || 0;
			const { tx, encEvent, encBackupEvent } =
				await this.initSurplusSequenceNumber.initSurplusSequenceNumber(
					latestSurplusSequenceNumber_newOwnerPublicKey
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
	async service_setInitialContractParams(req, res, next) {
		try {
			await startEventFilter("SyntheticPpaShield");
			const { strikePriceParam } = req.body;
			const { bundlePriceParam } = req.body;
			const { volumeShareParam } = req.body;
			const { numberOfConsecutivePeriodsForShortfallParam } = req.body;
			const { shortfallThresholdParam } = req.body;
			const { numberOfConsecutivePeriodsForSurplusParam } = req.body;
			const { surplusThresholdParam } = req.body;
			const { dailyInterestRateParam } = req.body;
			const { expiryDateOfContractParam } = req.body;
			const { sequenceNumberIntervalParam } = req.body;
			const { referenceDate } = req.body;
			const strikePrice_newOwnerPublicKey =
				req.body.strikePrice_newOwnerPublicKey || 0;
			const bundlePrice_newOwnerPublicKey =
				req.body.bundlePrice_newOwnerPublicKey || 0;
			const volumeShare_newOwnerPublicKey =
				req.body.volumeShare_newOwnerPublicKey || 0;
			const dailyInterestRate_newOwnerPublicKey =
				req.body.dailyInterestRate_newOwnerPublicKey || 0;
			const expiryDateOfContract_newOwnerPublicKey =
				req.body.expiryDateOfContract_newOwnerPublicKey || 0;
			const latestShortfallSequenceNumber_newOwnerPublicKey =
				req.body.latestShortfallSequenceNumber_newOwnerPublicKey || 0;
			const latestSurplusSequenceNumber_newOwnerPublicKey =
				req.body.latestSurplusSequenceNumber_newOwnerPublicKey || 0;
			const sequenceNumberInterval_newOwnerPublicKey =
				req.body.sequenceNumberInterval_newOwnerPublicKey || 0;
			const numberOfConsecutivePeriodsForShortfall_newOwnerPublicKey =
				req.body.numberOfConsecutivePeriodsForShortfall_newOwnerPublicKey || 0;
			const shortfallThreshold_newOwnerPublicKey =
				req.body.shortfallThreshold_newOwnerPublicKey || 0;
			const numberOfConsecutivePeriodsForSurplus_newOwnerPublicKey =
				req.body.numberOfConsecutivePeriodsForSurplus_newOwnerPublicKey || 0;
			const surplusThreshold_newOwnerPublicKey =
				req.body.surplusThreshold_newOwnerPublicKey || 0;
			const { tx, encEvent, encBackupEvent } =
				await this.setInitialContractParams.setInitialContractParams(
					strikePriceParam,
					bundlePriceParam,
					volumeShareParam,
					numberOfConsecutivePeriodsForShortfallParam,
					shortfallThresholdParam,
					numberOfConsecutivePeriodsForSurplusParam,
					surplusThresholdParam,
					dailyInterestRateParam,
					expiryDateOfContractParam,
					sequenceNumberIntervalParam,
					referenceDate,
					strikePrice_newOwnerPublicKey,
					bundlePrice_newOwnerPublicKey,
					volumeShare_newOwnerPublicKey,
					dailyInterestRate_newOwnerPublicKey,
					expiryDateOfContract_newOwnerPublicKey,
					latestShortfallSequenceNumber_newOwnerPublicKey,
					latestSurplusSequenceNumber_newOwnerPublicKey,
					sequenceNumberInterval_newOwnerPublicKey,
					numberOfConsecutivePeriodsForShortfall_newOwnerPublicKey,
					shortfallThreshold_newOwnerPublicKey,
					numberOfConsecutivePeriodsForSurplus_newOwnerPublicKey,
					surplusThreshold_newOwnerPublicKey
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
