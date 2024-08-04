// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);

    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(
        address recipient,
        uint256 amount
    ) external returns (bool);
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function allowance(
        address owner,
        address spender
    ) external view returns (uint256);

    function _transfer(
        address recipient,
        uint256 amount
    ) external returns (bool);
    // function _mint(address recipient, uint256 amount) external returns (bool);
    // function _mint(address recipient, uint256 amount) public returns (bool);
    function _burn(address recipient, uint256 amount) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );
}

contract ERC20 is IERC20 {
    // Specify the total supply of tokens
    uint256 public supply = 100;

    // Create a mapping to keep track of balances
    mapping(address => uint256) public balances;

    // Create a mapping to keep track of allowances
    mapping(address => mapping(address => uint256)) public allowances;

    // Specify the name of the token
    string public _name;

    // Specify the symbol of the token
    string public _symbol;

    // Specify the number of decimals for the token
    uint8 public _decimals = 18;

    // Initialize the total supply and allocate all tokens to the contract creator
    constructor(string memory name_, string memory symbol_) {
        balances[msg.sender] = supply;
        _name = name_;
        _symbol = symbol_;
    }

    function name() external view override returns (string memory) {
        return _name;
    }

    function symbol() external view override returns (string memory) {
        return _symbol;
    }

    function decimals() external view override returns (uint8) {
        return _decimals;
    }

    function totalSupply() external view override returns (uint256) {
        return supply;
    }

    function balanceOf(
        address account
    ) external view override returns (uint256) {
        return balances[account];
    }

    // Transfer tokens from the sender to the recipient, and emit the Transfer event
    function transfer(
        address recipient,
        uint256 amount
    ) external override returns (bool) {
        return performTransfer(msg.sender, recipient, amount);
    }

    function allowance(
        address owner,
        address spender
    ) external view override returns (uint256) {
        return allowances[owner][spender];
    }

    // Approve the spender to spend the specified amount of tokens on behalf of the owner, and emit the Approval event
    function approve(
        address spender,
        uint256 amount
    ) external override returns (bool) {
        allowances[msg.sender][spender] = amount; // previous sender->spender allowance is overwritten
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    // Transfer tokens from the sender to the recipient, and emit the Transfer event
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external override returns (bool) {
        require(
            allowances[sender][msg.sender] >= amount,
            "Insufficient allowance"
        );

        // seems unnecessary
        // bool c = performTransfer(sender, recipient, amount);
        // if (!c) return c;

        performTransfer(sender, recipient, amount);

        allowances[sender][msg.sender] -= amount;
        return true;
    }

    function _transfer(
        address recipient,
        uint256 amount
    ) external override returns (bool) {
        return performTransfer(msg.sender, recipient, amount);
    }

    function _mint(address recipient, uint256 amount) external returns (bool) {
        balances[recipient] += amount;
        supply += amount;

        emit Transfer(address(0), recipient, amount);
        return true;
    }

    function _burn(
        address recipient,
        uint256 amount
    ) external override returns (bool) {
        require(balances[recipient] >= amount, "Insufficient balance");
        balances[recipient] -= amount;
        supply -= amount;

        emit Transfer(recipient, address(0), amount);
        return true;
    }

    // this function actually performs the transfer, as the transfer function is external
    function performTransfer(
        address sender,
        address recipient,
        uint256 amount
    ) internal returns (bool) {
        require(balances[sender] >= amount, "Insufficient balance");

        balances[sender] -= amount;
        balances[recipient] += amount;

        emit Transfer(sender, recipient, amount);
        return true;
    }
}
