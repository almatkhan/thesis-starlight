import {
	service_allCommitments,
	service_getCommitmentsByState,
	service_reinstateNullifiers,
	service_getSharedKeys,
	service_getBalance,
	service_getBalanceByState,
	service_backupData,
} from "./api_services.mjs";

import express from "express";

export class Router {
	constructor(serviceMgr) {
		this.serviceMgr = serviceMgr;
	}
	addRoutes() {
		const router = express.Router();

		router.post(
			"/setStrikePrice",
			this.serviceMgr.service_setStrikePrice.bind(this.serviceMgr)
		);

		router.post(
			"/setBundlePrice",
			this.serviceMgr.service_setBundlePrice.bind(this.serviceMgr)
		);

		router.post(
			"/setShortfallThreshold",
			this.serviceMgr.service_setShortfallThreshold.bind(this.serviceMgr)
		);

		router.post(
			"/setShortfallPeriods",
			this.serviceMgr.service_setShortfallPeriods.bind(this.serviceMgr)
		);

		router.post(
			"/setSurplusThreshold",
			this.serviceMgr.service_setSurplusThreshold.bind(this.serviceMgr)
		);

		router.post(
			"/setSurplusPeriods",
			this.serviceMgr.service_setSurplusPeriods.bind(this.serviceMgr)
		);

		router.post(
			"/setDailyInterestRate",
			this.serviceMgr.service_setDailyInterestRate.bind(this.serviceMgr)
		);

		router.post(
			"/setExpiryDateOfContract",
			this.serviceMgr.service_setExpiryDateOfContract.bind(this.serviceMgr)
		);

		router.post(
			"/setVolumeShare",
			this.serviceMgr.service_setVolumeShare.bind(this.serviceMgr)
		);

		router.post(
			"/setSequenceNumberInterval",
			this.serviceMgr.service_setSequenceNumberInterval.bind(this.serviceMgr)
		);

		router.post(
			"/initSequenceNumber",
			this.serviceMgr.service_initSequenceNumber.bind(this.serviceMgr)
		);

		router.post(
			"/initSurplusSequenceNumber",
			this.serviceMgr.service_initSurplusSequenceNumber.bind(this.serviceMgr)
		);

		router.post(
			"/setInitialContractParams",
			this.serviceMgr.service_setInitialContractParams.bind(this.serviceMgr)
		);

		// commitment getter routes
		router.get("/getAllCommitments", service_allCommitments);
		router.get("/getCommitmentsByVariableName", service_getCommitmentsByState);
		router.get("/getBalance", service_getBalance);
		router.get("/getBalanceByState", service_getBalanceByState);
		// nullifier route
		router.post("/reinstateNullifiers", service_reinstateNullifiers);
		router.post("/getSharedKeys", service_getSharedKeys);
		// backup route
		router.post("/backupDataRetriever", service_backupData);

		return router;
	}
}
