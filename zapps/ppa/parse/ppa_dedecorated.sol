// SPDX-License-Identifier: CC0

pragma solidity ^0.8.0;
contract SyntheticPpa {
address public immutable owner;
uint256 private strikePrice;
uint256 private bundlePrice;
uint256 private volumeShare;
uint256 private dailyInterestRate;
uint256 private expiryDateOfContract;
bool public isContractTerminated;

mapping(uint256 => Shortfall) private shortfalls;
uint256 private latestShortfallSequenceNumber;

mapping(uint256 => Shortfall) private surplus;
uint256 private latestSurplusSequenceNumber;

uint256 private sequenceNumberInterval;

struct Shortfall {
uint256 billNumber;
uint256 volume;
uint256 price;
}

mapping(uint256 => uint256) private generatorCharges;
mapping(uint256 => uint256) private offtakerCharges;
mapping(uint256 => uint256) private generatorInterest;
mapping(uint256 => uint256) private offtakerInterest;
mapping(uint256 => uint256) private negativePriceCharges;

uint256 private numberOfConsecutivePeriodsForShortfall;
uint256 private shortfallThreshold;
uint256 private shortfallChargeSum;
uint256 private shortfallIndex;
mapping(uint256 => uint256) private shortfallCharges;

uint256 private numberOfConsecutivePeriodsForSurplus;
uint256 private surplusThreshold;
uint256 private surplusChargeSum;
uint256 private surplusIndex;
mapping(uint256 => uint256) private surplusCharges;

modifier onlyOwner() {
require(
msg.sender == owner,
"Caller is unauthorised, it must be the owner"
);
_;
}

constructor() {
owner = msg.sender;
}


function setStrikePrice(uint256 strikePriceParam) public onlyOwner {
require(
msg.sender == owner,
"Caller is unauthorised, it must be the owner"
);

strikePrice = strikePriceParam;
}

function setBundlePrice(uint256 bundlePriceParam) public onlyOwner {
require(
msg.sender == owner,
"Caller is unauthorised, it must be the owner"
);

bundlePrice = bundlePriceParam;
}

function setShortfallThreshold(uint256 shortfallThresholdParam) public onlyOwner {
require(
msg.sender == owner,
"Caller is unauthorised, it must be the owner"
);

shortfallThreshold = shortfallThresholdParam;
}

function setShortfallPeriods(uint256 shortfallPeriods) public onlyOwner {
require(
msg.sender == owner,
"Caller is unauthorised, it must be the owner"
);

numberOfConsecutivePeriodsForShortfall = shortfallPeriods;
}

function setSurplusThreshold(uint256 surplusThresholdParam) public onlyOwner {
require(
msg.sender == owner,
"Caller is unauthorised, it must be the owner"
);

surplusThreshold = surplusThresholdParam;
}

function setSurplusPeriods(uint256 surplusPeriods) public onlyOwner {
require(
msg.sender == owner,
"Caller is unauthorised, it must be the owner"
);

numberOfConsecutivePeriodsForSurplus = surplusPeriods;
}

function setDailyInterestRate(uint256 dailyInterestRateParam) public onlyOwner {
require(
msg.sender == owner,
"Caller is unauthorised, it must be the owner"
);

dailyInterestRate = dailyInterestRateParam;
}

function setExpiryDateOfContract(uint256 expiryDateOfContractParam) public onlyOwner {
require(
msg.sender == owner,
"Caller is unauthorised, it must be the owner"
);

expiryDateOfContract = expiryDateOfContractParam;
}

function setVolumeShare(uint256 volumeShareParam) public onlyOwner {
require(
msg.sender == owner,
"Caller is unauthorised, it must be the owner"
);

volumeShare = volumeShareParam;
}

function setSequenceNumberInterval(uint256 sequenceNumberIntervalParam) public onlyOwner {
require(
msg.sender == owner,
"Caller is unauthorised, it must be the owner"
);

sequenceNumberInterval = sequenceNumberIntervalParam;
}

function initSequenceNumber() public onlyOwner {
require(
msg.sender == owner,
"Caller is unauthorised, it must be the owner"
);

latestShortfallSequenceNumber = 0;
}

function initSurplusSequenceNumber() public onlyOwner {
require(
msg.sender == owner,
"Caller is unauthorised, it must be the owner"
);

latestSurplusSequenceNumber = 0;
}


function setInitialContractParams(


uint256 strikePriceParam,
uint256 bundlePriceParam,
uint256 volumeShareParam,
uint256 numberOfConsecutivePeriodsForShortfallParam,
uint256 shortfallThresholdParam,
uint256 numberOfConsecutivePeriodsForSurplusParam,
uint256 surplusThresholdParam,
uint256 dailyInterestRateParam,
uint256 expiryDateOfContractParam,
uint256 sequenceNumberIntervalParam,
uint256 referenceDate
) public onlyOwner {
require(referenceDate > expiryDateOfContract);

require(isContractTerminated == false);
volumeShare = volumeShareParam;
strikePrice = strikePriceParam;
bundlePrice = bundlePriceParam;
numberOfConsecutivePeriodsForShortfall = numberOfConsecutivePeriodsForShortfallParam;
shortfallThreshold = shortfallThresholdParam;
numberOfConsecutivePeriodsForSurplus = numberOfConsecutivePeriodsForSurplusParam;
surplusThreshold = surplusThresholdParam;
dailyInterestRate = dailyInterestRateParam;
expiryDateOfContract = expiryDateOfContractParam;
sequenceNumberInterval = sequenceNumberIntervalParam;
latestShortfallSequenceNumber = 0;
latestSurplusSequenceNumber = 0;
}


// function calculateCfd(
// secret uint256 billNumber,
// secret uint256 sequenceNumber,
// secret uint256 totalGeneratedVolume,
// secret uint256 expectedVolume,
// secret uint256 averagePrice,
// secret uint256 marginalLossFactor,
// secret uint256 floatingAmount,
// secret uint256 positiveAdjustment,
// secret uint256 negativeAdjustment,
// secret uint256[5] calldata outstandingGeneratorAmount,
// secret uint256[5] calldata outstandingOfftakerAmount,
// secret uint256[5] calldata generatorDelayDays,
// secret uint256[5] calldata offtakerDelayDays,
// secret uint256 referenceDate
// ) public onlyOwner
// returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256) {

// require(referenceDate < expiryDateOfContract);
// require(isContractTerminated == false);

// secret uint256 offtakerVolume = totalGeneratedVolume * volumeShare;
// secret uint256 fixedAmount = offtakerVolume * bundlePrice * marginalLossFactor;
// negativePriceCharges[billNumber] = expectedVolume * strikePrice - totalGeneratedVolume * strikePrice;
// secret uint256 index = shortfallIndex + 1;
// secret uint256 tempSurplusIndex = surplusIndex + 1; 

// if (floatingAmount > fixedAmount) {
// generatorCharges[billNumber] = floatingAmount - fixedAmount + positiveAdjustment - negativeAdjustment;
// } else {
// offtakerCharges[billNumber] = fixedAmount - floatingAmount + positiveAdjustment - negativeAdjustment;
// }

// secret bool shortfallSequence = false;
// if(sequenceNumber == latestShortfallSequenceNumber + sequenceNumberInterval ||
// latestShortfallSequenceNumber == 0 ||
// sequenceNumber == 0
// ) {
// shortfallSequence = true;
// }

// secret bool surplusSequence = false;
// if(sequenceNumber == latestSurplusSequenceNumber + sequenceNumberInterval ||
// latestSurplusSequenceNumber == 0 ||
// sequenceNumber == 0
// ) {
// surplusSequence = true;
// }

// secret uint256 priceDifference = 0;
// if(averagePrice > strikePrice) {
// priceDifference = averagePrice - strikePrice;
// } else {
// priceDifference = strikePrice - averagePrice;
// }

// // Shortfall and suplus difference
// secret uint256 volumeDifference = 0;
// if(expectedVolume > offtakerVolume) { 
// volumeDifference = expectedVolume - totalGeneratedVolume;
// } else {
// volumeDifference = totalGeneratedVolume - expectedVolume;
// }


// // Shortfall calculation
// if (shortfallSequence && expectedVolume > offtakerVolume && volumeDifference >= shortfallThreshold) {
// shortfalls[index].billNumber = billNumber;
// shortfalls[index].price = averagePrice;
// shortfalls[index].volume = shortfallThreshold - offtakerVolume; 
// shortfallChargeSum += shortfalls[index].volume * priceDifference;
// shortfallIndex += 1;
// latestShortfallSequenceNumber = sequenceNumber;
// } 

// if (shortfallSequence && expectedVolume < offtakerVolume || volumeDifference <= shortfallThreshold) {
// shortfallChargeSum = 0;
// shortfallIndex = 0;
// latestShortfallSequenceNumber = 0;
// }

// if (shortfallIndex >= numberOfConsecutivePeriodsForShortfall) {
// shortfallCharges[billNumber] = shortfallChargeSum;
// shortfallChargeSum = 0;
// shortfallIndex = 0;
// latestShortfallSequenceNumber = 0;
// }

// // Surplus calculation
// if (surplusSequence && expectedVolume < offtakerVolume && volumeDifference >= surplusThreshold) {
// surplus[tempSurplusIndex].billNumber = billNumber;
// surplus[tempSurplusIndex].price = averagePrice;
// surplus[tempSurplusIndex].volume = surplusThreshold - offtakerVolume; 
// surplusChargeSum += surplus[tempSurplusIndex].volume * priceDifference;
// surplusIndex += 1;
// latestSurplusSequenceNumber = sequenceNumber;
// } 

// if (surplusSequence && expectedVolume > offtakerVolume || volumeDifference <= surplusThreshold) {
// surplusChargeSum = 0;
// surplusIndex = 0;
// latestSurplusSequenceNumber = 0;
// }

// if (surplusIndex >= numberOfConsecutivePeriodsForSurplus) {
// surplusCharges[billNumber] = surplusChargeSum;
// surplusChargeSum = 0;
// surplusIndex = 0;
// latestSurplusSequenceNumber = 0;
// }

// for (uint256 i = 0; i < 5; i++) {
// if (outstandingGeneratorAmount[i] > 0) {
// generatorInterest[billNumber] += outstandingGeneratorAmount[i] * generatorDelayDays[i] * dailyInterestRate;
// } if (outstandingOfftakerAmount[i] > 0) {
// offtakerInterest[billNumber] += outstandingOfftakerAmount[i] * offtakerDelayDays[i] * dailyInterestRate;
// }
// }

// return (
// generatorCharges[billNumber],
// offtakerCharges[billNumber],
// generatorInterest[billNumber],
// offtakerInterest[billNumber],
// shortfallCharges[billNumber],
// surplusCharges[billNumber],
// negativePriceCharges[billNumber]
// );
// }


// function terminateContract() public onlyOwner {
// isContractTerminated = true;
// }
}