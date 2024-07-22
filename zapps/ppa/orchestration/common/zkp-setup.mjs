/**
Module to set up zkp elements of compiler output, along with writing the vks to the db folder. To be run from inside the zokrates container.
*/

import fs from "fs";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import { generateKeys } from "./zokrates.mjs";

// const { generalise } = GN;
const argv = yargs(hideBin(process.argv))
	.usage("Usage: $0 -i <input file>")
	.demandOption(["i"]).argv;
const functionNames = [
	"setStrikePrice",
	"setBundlePrice",
	"setShortfallThreshold",
	"setShortfallPeriods",
	"setSurplusThreshold",
	"setSurplusPeriods",
	"setDailyInterestRate",
	"setExpiryDateOfContract",
	"setVolumeShare",
	"setSequenceNumberInterval",
	"initSequenceNumber",
	"initSurplusSequenceNumber",
	"setInitialContractParams",
];

export const setup = async (functionName) => {
	if (!functionName) {
		for (const name of functionNames) {
			await generateKeys(`${name}.zok`);
		}
	} else {
		await generateKeys(`${functionName}.zok`);
	}
};

setup(argv.i);
