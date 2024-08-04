// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./erc20.sol";

contract ZKSender {
IERC20 public immutable token;
uint256 public reserve;

mapping(address => uint256) balances;

constructor(address _token) {
token = IERC20(_token);
}

// This function hides the tokens and makes them only accessible via ZKP
function vault(uint256 amountIn) public {
// First, transfer the funds from the user to this contract (lock funds)
require(amountIn > 0, "Amount must be greater than 0");
require(
token.transferFrom(msg.sender, address(this), amountIn),
"Transfer failed"
);

// Then, update the balance of the user in the ZKP way
balances[msg.sender] += amountIn;
reserve += amountIn;
}

function send(address recipient, uint256 amount) public {
// Deduct the amount from the sender's balance
balances[msg.sender] -= amount;
// Add the amount to the recipient's balance
balances[recipient] += amount;
}

// // This function allows the user to withdraw the funds from the vault
// // Important, this function should not be vulnerable to reentrancy attacks.
// // - However, this is not tested against reentrancy attacks.
// // NOTICE: This function UNHIDES the tokens and makes anyone able to see them
function unVault(uint256 amountOut) public {
require(reserve >= amountOut, "WTF, IT SHOULD NEVER HAPPEN! WE'VE BEEN HACKED!");

balances[msg.sender] -= amountOut;
reserve -= amountOut;

require(token.transfer(msg.sender, amountOut), "Transfer failed");
}
}
