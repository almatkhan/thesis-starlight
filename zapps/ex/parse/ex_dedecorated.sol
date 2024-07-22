// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IERC20 {
    function totalSupply() external view returns (uint);
    function balanceOf(address account) external view returns (uint);

    function transfer(address recipient, uint amount) external returns (bool);

    function allowance(
        address owner,
        address spender
    ) external view returns (uint);

    function approve(address spender, uint amount) external returns (bool);

    function transferFrom(
        address sender,
        address recipient,
        uint amount
    ) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint amount);
    event Approval(address indexed owner, address indexed spender, uint amount);
}

contract ZKSender {
    IERC20 public immutable token;
    uint public reserve;

    mapping(address => uint) balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // This function hides the tokens and makes them only accessible via ZKP
    function vault(uint _amountIn) external returns (bool) {
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

    // This function UNhides the tokens and makes them transparently accissable
    // For the simplicity this function supports only full withdrawals.
    // No partial withdrawals
    function unvault() external returns (bool) {
        uint amount = balances[msg.sender];

        require(amount > 0, "You have no funds available");
        require(reserve >= amount, "Unsufficiant funds"); // This should never happen!
        require(
            token.transferFrom(address(this), msg.sender, amount),
            "Transfer failed"
        );

        reserve -= amount;

        // We could apply some fees here, if we wanted to

        // Emit something? A commitment change?

        return true;
    }

    // This function sends the funds within the ZKP
    function transfer(address recipient, uint amount) external returns (bool) {
        require(amount > 0, "Amount must be greater than 0");

        balances[msg.sender] -= amount;
        balances[recipient] += amount;

        // Emit something? A commitment change?

        return true;
    }
}
