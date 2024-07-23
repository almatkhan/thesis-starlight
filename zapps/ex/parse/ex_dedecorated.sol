// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IERC20 {
function totalSupply() external view returns (uint256);
function balanceOf(address account) external view returns (uint256);

function transfer(address recipient, uint256 amount) external returns (bool);

function allowance(
address owner,
address spender
) external view returns (uint256);

function approve(address spender, uint256 amount) external returns (bool);

function transferFrom(
address sender,
address recipient,
uint256 amount
) external returns (bool);

event Transfer(address indexed from, address indexed to, uint256 amount);
event Approval(address indexed owner, address indexed spender, uint256 amount);
}

contract ZKSender {
IERC20 public immutable token;
uint256 public reserve;

mapping(address => uint256) balances;

constructor(address _token) {
token = IERC20(_token);
}

// This function hides the tokens and makes them only accessible via ZKP
function vault(uint256 _amountIn) external returns (bool) {
// First, transfer the funds from the user to this contract (lock funds)
require(_amountIn > 0, "Amount must be greater than 0");
require(
token.transferFrom(msg.sender, address(this), _amountIn),
"Transfer failed"
);

// Then, update the balance of the user in the ZKP way
balances[msg.sender] += _amountIn;

reserve += _amountIn;

// We could apply some fees here.
// Alternatively, they could be applied on withdrawal
// emit something? Emit a commitment change?

return true;
}

function unVault(uint256 _amountOut) external returns (bool){
require(balances[msg.sender] >= _amountOut, "Unsufficient funds");
require(reserve >= _amountOut, "WTF, IT SHOULD NEVER HAPPEN! WE'VE BEEN HACKED!");
require(token.transfer(msg.sender, _amountOut), "Transfer failed");

balances[msg.sender] -= _amountOut;
reserve -= _amountOut;

return true;
}
}
