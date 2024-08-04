// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./verify/IVerifier.sol";
import "./merkle-tree/MerkleTree.sol";

import "./erc20.sol";

contract ZKSenderShield is MerkleTree {
    enum FunctionNames {
        vault,
        send,
        unVault,
        joinCommitments,
        splitCommitments
    }

    IVerifier private verifier;

    mapping(uint256 => uint256[]) public vks; // indexed to by an enum uint(FunctionNames)

    struct BackupDataElement {
        string varName;
        uint256[] cipherText;
        uint256 ephPublicKey;
    }

    event EncryptedBackupData(BackupDataElement[] encPreimages);

    uint256 public newNullifierRoot;

    mapping(uint256 => uint256) public commitmentRoots;

    uint256 public latestRoot;

    mapping(address => uint256) public zkpPublicKeys;

    struct Inputs {
        uint nullifierRoot;
        uint latestNullifierRoot;
        uint[] newNullifiers;
        uint commitmentRoot;
        uint[] newCommitments;
        uint[] customInputs;
    }

    function registerZKPPublicKey(uint256 pk) external {
        zkpPublicKeys[msg.sender] = pk;
    }

    function verify(
        uint256[] memory proof,
        uint256 functionId,
        Inputs memory _inputs
    ) private {
        uint[] memory customInputs = _inputs.customInputs;

        uint[] memory newNullifiers = _inputs.newNullifiers;

        uint[] memory newCommitments = _inputs.newCommitments;

        require(
            commitmentRoots[_inputs.commitmentRoot] == _inputs.commitmentRoot,
            "Input commitmentRoot does not exist."
        );

        uint256[] memory inputs = new uint256[](
            customInputs.length +
                newNullifiers.length +
                (newNullifiers.length > 0 ? 3 : 0) +
                newCommitments.length
        );

        if (functionId == uint(FunctionNames.vault)) {
            uint k = 0;

            inputs[k++] = customInputs[0];
            inputs[k++] = newCommitments[0];
            inputs[k++] = 1;
        }

        if (functionId == uint(FunctionNames.send)) {
            uint k = 0;

            require(
                newNullifierRoot == _inputs.nullifierRoot,
                "Input NullifierRoot does not exist."
            );
            inputs[k++] = _inputs.nullifierRoot;
            inputs[k++] = _inputs.latestNullifierRoot;
            inputs[k++] = newNullifiers[0];
            inputs[k++] = newNullifiers[1];
            inputs[k++] = _inputs.commitmentRoot;
            inputs[k++] = newCommitments[0];
            inputs[k++] = newCommitments[1];
            inputs[k++] = 1;
        }

        if (functionId == uint(FunctionNames.unVault)) {
            uint k = 0;

            require(
                newNullifierRoot == _inputs.nullifierRoot,
                "Input NullifierRoot does not exist."
            );
            inputs[k++] = customInputs[0];
            inputs[k++] = _inputs.nullifierRoot;
            inputs[k++] = _inputs.latestNullifierRoot;
            inputs[k++] = newNullifiers[0];
            inputs[k++] = newNullifiers[1];
            inputs[k++] = _inputs.commitmentRoot;
            inputs[k++] = newCommitments[0];
            inputs[k++] = 1;
        }

        if (functionId == uint(FunctionNames.joinCommitments)) {
            require(
                newNullifierRoot == _inputs.nullifierRoot,
                "Input NullifierRoot does not exist."
            );

            uint k = 0;

            inputs[k++] = _inputs.nullifierRoot;
            inputs[k++] = _inputs.latestNullifierRoot;
            inputs[k++] = newNullifiers[0];
            inputs[k++] = newNullifiers[1];
            inputs[k++] = _inputs.commitmentRoot;
            inputs[k++] = newCommitments[0];
            inputs[k++] = 1;
        }

        if (functionId == uint(FunctionNames.splitCommitments)) {
            require(
                newNullifierRoot == _inputs.nullifierRoot,
                "Input NullifierRoot does not exist."
            );

            uint k = 0;

            inputs[k++] = _inputs.nullifierRoot;
            inputs[k++] = _inputs.latestNullifierRoot;
            inputs[k++] = newNullifiers[0];
            inputs[k++] = _inputs.commitmentRoot;
            inputs[k++] = newCommitments[0];
            inputs[k++] = newCommitments[1];
            inputs[k++] = 1;
        }

        bool result = verifier.verify(proof, inputs, vks[functionId]);

        require(result, "The proof has not been verified by the contract");

        if (newCommitments.length > 0) {
            latestRoot = insertLeaves(newCommitments);
            commitmentRoots[latestRoot] = latestRoot;
        }

        if (newNullifiers.length > 0) {
            newNullifierRoot = _inputs.latestNullifierRoot;
        }
    }

    function joinCommitments(
        uint256 nullifierRoot,
        uint256 latestNullifierRoot,
        uint256[] calldata newNullifiers,
        uint256 commitmentRoot,
        uint256[] calldata newCommitments,
        uint256[] calldata proof
    ) public {
        Inputs memory inputs;

        inputs.customInputs = new uint[](1);
        inputs.customInputs[0] = 1;

        inputs.nullifierRoot = nullifierRoot;

        inputs.latestNullifierRoot = latestNullifierRoot;

        inputs.newNullifiers = newNullifiers;

        inputs.commitmentRoot = commitmentRoot;

        inputs.newCommitments = newCommitments;

        verify(proof, uint(FunctionNames.joinCommitments), inputs);
    }

    function splitCommitments(
        uint256 nullifierRoot,
        uint256 latestNullifierRoot,
        uint256[] calldata newNullifiers,
        uint256 commitmentRoot,
        uint256[] calldata newCommitments,
        uint256[] calldata proof
    ) public {
        Inputs memory inputs;

        inputs.customInputs = new uint[](1);
        inputs.customInputs[0] = 1;

        inputs.nullifierRoot = nullifierRoot;

        inputs.latestNullifierRoot = latestNullifierRoot;

        inputs.newNullifiers = newNullifiers;

        inputs.commitmentRoot = commitmentRoot;

        inputs.newCommitments = newCommitments;

        verify(proof, uint(FunctionNames.splitCommitments), inputs);
    }

    IERC20 public token;

    uint256 public reserve;

    constructor(
        address _token,
        address verifierAddress,
        uint256[][] memory vk
    ) {
        verifier = IVerifier(verifierAddress);
        for (uint i = 0; i < vk.length; i++) {
            vks[i] = vk[i];
        }
        newNullifierRoot = Initial_NullifierRoot;
        token = IERC20(_token);
    }

    function vault(
        uint256 amountIn,
        Inputs calldata inputs,
        uint256[] calldata proof,
        BackupDataElement[] memory BackupData
    ) public {
        Inputs memory updatedInputs = inputs;
        updatedInputs.customInputs = new uint[](2);
        updatedInputs.customInputs[0] = amountIn;
        updatedInputs.customInputs[1] = 1;
        verify(proof, uint(FunctionNames.vault), updatedInputs);

        // this seems silly (it is) but its the only way to get the event to emit properly
        emit EncryptedBackupData(BackupData);
        require(amountIn > 0, "Amount must be greater than 0");
        require(
            token.transferFrom(msg.sender, address(this), amountIn),
            "Transfer failed"
        );

        reserve += amountIn;
    }

    function send(
        Inputs calldata inputs,
        uint256[] calldata proof,
        BackupDataElement[] memory BackupData
    ) public {
        verify(proof, uint(FunctionNames.send), inputs);

        // this seems silly (it is) but its the only way to get the event to emit properly
        emit EncryptedBackupData(BackupData);
    }

    function unVault(
        uint256 amountOut,
        Inputs calldata inputs,
        uint256[] calldata proof,
        BackupDataElement[] memory BackupData
    ) public {
        Inputs memory updatedInputs = inputs;
        updatedInputs.customInputs = new uint[](2);
        updatedInputs.customInputs[0] = amountOut;
        updatedInputs.customInputs[1] = 1;
        verify(proof, uint(FunctionNames.unVault), updatedInputs);

        // this seems silly (it is) but its the only way to get the event to emit properly
        emit EncryptedBackupData(BackupData);
        require(
            reserve >= amountOut,
            "WTF, IT SHOULD NEVER HAPPEN! WE'VE BEEN HACKED!"
        );

        reserve -= amountOut;
        require(token.transfer(msg.sender, amountOut), "Transfer failed");
    }
}
