const fs = require("fs");

const Pairing = artifacts.require("Pairing");
const Verifier = artifacts.require("Verifier");

const ZKSenderShield = artifacts.require("ZKSenderShield");
const Token = artifacts.require("ERC20"); // Add your ERC20 token contract

const functionNames = [
	"vault",
	"send",
	"unVault",
	"joinCommitments",
	"splitCommitments",
];
const vkInput = [];
let vk = [];
functionNames.forEach((name) => {
	const vkJson = JSON.parse(
		fs.readFileSync(`/app/orchestration/common/db/${name}_vk.key`, "utf-8")
	);
	if (vkJson.scheme) {
		vk = Object.values(vkJson).slice(2).flat(Infinity);
	} else {
		vk = Object.values(vkJson).flat(Infinity);
	}
	vkInput.push(vk);
});

module.exports = (deployer) => {
	deployer.then(async () => {
		// Deploy the ERC20 token
		const tokenInstance = await deployer.deploy(Token, "ZKToken", "ZKT");
		

		await deployer.deploy(Pairing);
		await deployer.link(Pairing, Verifier);
		await deployer.deploy(Verifier);

		await deployer.deploy(ZKSenderShield, Verifier.address, vkInput, tokenInstance.address);
	});
};
