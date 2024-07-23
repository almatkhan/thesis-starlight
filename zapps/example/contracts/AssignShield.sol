// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./verify/IVerifier.sol";
import "./merkle-tree/MerkleTree.sol";

contract AssignShield is MerkleTree {


          enum FunctionNames { add }

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


        constructor (
      		address verifierAddress,
      		uint256[][] memory vk
      	) {
      		verifier = IVerifier(verifierAddress);
      		for (uint i = 0; i < vk.length; i++) {
      			vks[i] = vk[i];
      		}

          newNullifierRoot = Initial_NullifierRoot;

        }


        function registerZKPPublicKey(uint256 pk) external {
      		zkpPublicKeys[msg.sender] = pk;
      	}
        


        function verify(
      		uint256[] calldata proof,
      		uint256 functionId,
      		Inputs memory _inputs
      	) private {
        
          uint[] memory customInputs = _inputs.customInputs;

          uint[] memory newNullifiers = _inputs.newNullifiers;

          uint[] memory newCommitments = _inputs.newCommitments;

          require(commitmentRoots[_inputs.commitmentRoot] == _inputs.commitmentRoot, "Input commitmentRoot does not exist.");

            uint256[] memory inputs = new uint256[](customInputs.length + newNullifiers.length + (newNullifiers.length > 0 ? 3 : 0) + newCommitments.length);
          
          if (functionId == uint(FunctionNames.add)) {
            uint k = 0;
             
            require(newNullifierRoot == _inputs.nullifierRoot, "Input NullifierRoot does not exist.");
            inputs[k++] = customInputs[0];
            inputs[k++] = customInputs[1];
            inputs[k++] = _inputs.nullifierRoot;
            inputs[k++] = _inputs.latestNullifierRoot;
            inputs[k++] = newNullifiers[0];
            inputs[k++] = _inputs.commitmentRoot;
            inputs[k++] = newCommitments[0];
            inputs[k++] = newNullifiers[1];
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







        bool public d;


        bool public g;


      function add (bool value_publicbool, Inputs calldata inputs, uint256[] calldata proof, BackupDataElement[] memory BackupData) public  {

        
          Inputs memory updatedInputs = inputs;
          updatedInputs.customInputs = new uint[](3);
        	updatedInputs.customInputs[0] = value_publicbool == false ? 0 : 1;
updatedInputs.customInputs[1] = d == false ? 0 : 1;
updatedInputs.customInputs[2] = 1;
           verify(proof, uint(FunctionNames.add), updatedInputs);

            // this seems silly (it is) but its the only way to get the event to emit properly
            emit EncryptedBackupData(BackupData);

          bool m = false;

        
      }
}