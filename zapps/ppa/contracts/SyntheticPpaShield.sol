// SPDX-License-Identifier: CC0

pragma solidity ^0.8.0;

import "./verify/IVerifier.sol";
import "./merkle-tree/MerkleTree.sol";

contract SyntheticPpaShield is MerkleTree {


          enum FunctionNames { setStrikePrice, setBundlePrice, setShortfallThreshold, setShortfallPeriods, setSurplusThreshold, setSurplusPeriods, setDailyInterestRate, setExpiryDateOfContract, setVolumeShare, setSequenceNumberInterval, initSequenceNumber, initSurplusSequenceNumber, setInitialContractParams }

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

          require(commitmentRoots[_inputs.commitmentRoot] == _inputs.commitmentRoot, "Input commitmentRoot does not exist.");

            uint256[] memory inputs = new uint256[](customInputs.length + newNullifiers.length + (newNullifiers.length > 0 ? 3 : 0) + newCommitments.length);
          
          if (functionId == uint(FunctionNames.setStrikePrice)) {
            uint k = 0;
             
            require(newNullifierRoot == _inputs.nullifierRoot, "Input NullifierRoot does not exist.");
            inputs[k++] = _inputs.nullifierRoot;
            inputs[k++] = _inputs.latestNullifierRoot;
            inputs[k++] = newNullifiers[0];
            inputs[k++] = _inputs.commitmentRoot;
            inputs[k++] = newCommitments[0];
            inputs[k++] = 1;
            
          }

          if (functionId == uint(FunctionNames.setBundlePrice)) {
            uint k = 0;
             
            require(newNullifierRoot == _inputs.nullifierRoot, "Input NullifierRoot does not exist.");
            inputs[k++] = _inputs.nullifierRoot;
            inputs[k++] = _inputs.latestNullifierRoot;
            inputs[k++] = newNullifiers[0];
            inputs[k++] = _inputs.commitmentRoot;
            inputs[k++] = newCommitments[0];
            inputs[k++] = 1;
            
          }

          if (functionId == uint(FunctionNames.setShortfallThreshold)) {
            uint k = 0;
             
            require(newNullifierRoot == _inputs.nullifierRoot, "Input NullifierRoot does not exist.");
            inputs[k++] = _inputs.nullifierRoot;
            inputs[k++] = _inputs.latestNullifierRoot;
            inputs[k++] = newNullifiers[0];
            inputs[k++] = _inputs.commitmentRoot;
            inputs[k++] = newCommitments[0];
            inputs[k++] = 1;
            
          }

          if (functionId == uint(FunctionNames.setShortfallPeriods)) {
            uint k = 0;
             
            require(newNullifierRoot == _inputs.nullifierRoot, "Input NullifierRoot does not exist.");
            inputs[k++] = _inputs.nullifierRoot;
            inputs[k++] = _inputs.latestNullifierRoot;
            inputs[k++] = newNullifiers[0];
            inputs[k++] = _inputs.commitmentRoot;
            inputs[k++] = newCommitments[0];
            inputs[k++] = 1;
            
          }

          if (functionId == uint(FunctionNames.setSurplusThreshold)) {
            uint k = 0;
             
            require(newNullifierRoot == _inputs.nullifierRoot, "Input NullifierRoot does not exist.");
            inputs[k++] = _inputs.nullifierRoot;
            inputs[k++] = _inputs.latestNullifierRoot;
            inputs[k++] = newNullifiers[0];
            inputs[k++] = _inputs.commitmentRoot;
            inputs[k++] = newCommitments[0];
            inputs[k++] = 1;
            
          }

          if (functionId == uint(FunctionNames.setSurplusPeriods)) {
            uint k = 0;
             
            require(newNullifierRoot == _inputs.nullifierRoot, "Input NullifierRoot does not exist.");
            inputs[k++] = _inputs.nullifierRoot;
            inputs[k++] = _inputs.latestNullifierRoot;
            inputs[k++] = newNullifiers[0];
            inputs[k++] = _inputs.commitmentRoot;
            inputs[k++] = newCommitments[0];
            inputs[k++] = 1;
            
          }

          if (functionId == uint(FunctionNames.setDailyInterestRate)) {
            uint k = 0;
             
            require(newNullifierRoot == _inputs.nullifierRoot, "Input NullifierRoot does not exist.");
            inputs[k++] = _inputs.nullifierRoot;
            inputs[k++] = _inputs.latestNullifierRoot;
            inputs[k++] = newNullifiers[0];
            inputs[k++] = _inputs.commitmentRoot;
            inputs[k++] = newCommitments[0];
            inputs[k++] = 1;
            
          }

          if (functionId == uint(FunctionNames.setExpiryDateOfContract)) {
            uint k = 0;
             
            require(newNullifierRoot == _inputs.nullifierRoot, "Input NullifierRoot does not exist.");
            inputs[k++] = _inputs.nullifierRoot;
            inputs[k++] = _inputs.latestNullifierRoot;
            inputs[k++] = newNullifiers[0];
            inputs[k++] = _inputs.commitmentRoot;
            inputs[k++] = newCommitments[0];
            inputs[k++] = 1;
            
          }

          if (functionId == uint(FunctionNames.setVolumeShare)) {
            uint k = 0;
             
            require(newNullifierRoot == _inputs.nullifierRoot, "Input NullifierRoot does not exist.");
            inputs[k++] = _inputs.nullifierRoot;
            inputs[k++] = _inputs.latestNullifierRoot;
            inputs[k++] = newNullifiers[0];
            inputs[k++] = _inputs.commitmentRoot;
            inputs[k++] = newCommitments[0];
            inputs[k++] = 1;
            
          }

          if (functionId == uint(FunctionNames.setSequenceNumberInterval)) {
            uint k = 0;
             
            require(newNullifierRoot == _inputs.nullifierRoot, "Input NullifierRoot does not exist.");
            inputs[k++] = _inputs.nullifierRoot;
            inputs[k++] = _inputs.latestNullifierRoot;
            inputs[k++] = newNullifiers[0];
            inputs[k++] = _inputs.commitmentRoot;
            inputs[k++] = newCommitments[0];
            inputs[k++] = 1;
            
          }

          if (functionId == uint(FunctionNames.initSequenceNumber)) {
            uint k = 0;
             
            require(newNullifierRoot == _inputs.nullifierRoot, "Input NullifierRoot does not exist.");
            inputs[k++] = _inputs.nullifierRoot;
            inputs[k++] = _inputs.latestNullifierRoot;
            inputs[k++] = newNullifiers[0];
            inputs[k++] = _inputs.commitmentRoot;
            inputs[k++] = newCommitments[0];
            inputs[k++] = 1;
            
          }

          if (functionId == uint(FunctionNames.initSurplusSequenceNumber)) {
            uint k = 0;
             
            require(newNullifierRoot == _inputs.nullifierRoot, "Input NullifierRoot does not exist.");
            inputs[k++] = _inputs.nullifierRoot;
            inputs[k++] = _inputs.latestNullifierRoot;
            inputs[k++] = newNullifiers[0];
            inputs[k++] = _inputs.commitmentRoot;
            inputs[k++] = newCommitments[0];
            inputs[k++] = 1;
            
          }

          if (functionId == uint(FunctionNames.setInitialContractParams)) {
            uint k = 0;
             
            require(newNullifierRoot == _inputs.nullifierRoot, "Input NullifierRoot does not exist.");
            inputs[k++] = _inputs.nullifierRoot;
            inputs[k++] = _inputs.latestNullifierRoot;
            inputs[k++] = newNullifiers[0];
            inputs[k++] = _inputs.commitmentRoot;
            inputs[k++] = newCommitments[0];
            inputs[k++] = newNullifiers[1];
            inputs[k++] = newCommitments[1];
            inputs[k++] = newNullifiers[2];
            inputs[k++] = newCommitments[2];
            inputs[k++] = newNullifiers[3];
            inputs[k++] = newCommitments[3];
            inputs[k++] = newNullifiers[4];
            inputs[k++] = newCommitments[4];
            inputs[k++] = newNullifiers[5];
            inputs[k++] = newCommitments[5];
            inputs[k++] = newNullifiers[6];
            inputs[k++] = newCommitments[6];
            inputs[k++] = newNullifiers[7];
            inputs[k++] = newCommitments[7];
            inputs[k++] = newNullifiers[8];
            inputs[k++] = newCommitments[8];
            inputs[k++] = newNullifiers[9];
            inputs[k++] = newCommitments[9];
            inputs[k++] = newNullifiers[10];
            inputs[k++] = newCommitments[10];
            inputs[k++] = newNullifiers[11];
            inputs[k++] = newCommitments[11];
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



        address public owner;












        bool public isContractTerminated;











struct Shortfall {
        
        uint256 billNumber;

        uint256 volume;

        uint256 price;
      }
































      constructor  (address verifierAddress, uint256[][] memory vk)   {

         verifier = IVerifier(verifierAddress);
    		  for (uint i = 0; i < vk.length; i++) {
    			  vks[i] = vk[i];
    		  }
          newNullifierRoot = Initial_NullifierRoot;
owner = msg.sender;
        
      }


      function setStrikePrice (Inputs calldata inputs, uint256[] calldata proof, BackupDataElement[] memory BackupData) public  {

         verify(proof, uint(FunctionNames.setStrikePrice), inputs);

            // this seems silly (it is) but its the only way to get the event to emit properly
            emit EncryptedBackupData(BackupData);
require(msg.sender == owner, "Caller is unauthorised, it must be the owner");

        
      }


      function setBundlePrice (Inputs calldata inputs, uint256[] calldata proof, BackupDataElement[] memory BackupData) public  {

         verify(proof, uint(FunctionNames.setBundlePrice), inputs);

            // this seems silly (it is) but its the only way to get the event to emit properly
            emit EncryptedBackupData(BackupData);
require(msg.sender == owner, "Caller is unauthorised, it must be the owner");

        
      }


      function setShortfallThreshold (Inputs calldata inputs, uint256[] calldata proof, BackupDataElement[] memory BackupData) public  {

         verify(proof, uint(FunctionNames.setShortfallThreshold), inputs);

            // this seems silly (it is) but its the only way to get the event to emit properly
            emit EncryptedBackupData(BackupData);
require(msg.sender == owner, "Caller is unauthorised, it must be the owner");

        
      }


      function setShortfallPeriods (Inputs calldata inputs, uint256[] calldata proof, BackupDataElement[] memory BackupData) public  {

         verify(proof, uint(FunctionNames.setShortfallPeriods), inputs);

            // this seems silly (it is) but its the only way to get the event to emit properly
            emit EncryptedBackupData(BackupData);
require(msg.sender == owner, "Caller is unauthorised, it must be the owner");

        
      }


      function setSurplusThreshold (Inputs calldata inputs, uint256[] calldata proof, BackupDataElement[] memory BackupData) public  {

         verify(proof, uint(FunctionNames.setSurplusThreshold), inputs);

            // this seems silly (it is) but its the only way to get the event to emit properly
            emit EncryptedBackupData(BackupData);
require(msg.sender == owner, "Caller is unauthorised, it must be the owner");

        
      }


      function setSurplusPeriods (Inputs calldata inputs, uint256[] calldata proof, BackupDataElement[] memory BackupData) public  {

         verify(proof, uint(FunctionNames.setSurplusPeriods), inputs);

            // this seems silly (it is) but its the only way to get the event to emit properly
            emit EncryptedBackupData(BackupData);
require(msg.sender == owner, "Caller is unauthorised, it must be the owner");

        
      }


      function setDailyInterestRate (Inputs calldata inputs, uint256[] calldata proof, BackupDataElement[] memory BackupData) public  {

         verify(proof, uint(FunctionNames.setDailyInterestRate), inputs);

            // this seems silly (it is) but its the only way to get the event to emit properly
            emit EncryptedBackupData(BackupData);
require(msg.sender == owner, "Caller is unauthorised, it must be the owner");

        
      }


      function setExpiryDateOfContract (Inputs calldata inputs, uint256[] calldata proof, BackupDataElement[] memory BackupData) public  {

         verify(proof, uint(FunctionNames.setExpiryDateOfContract), inputs);

            // this seems silly (it is) but its the only way to get the event to emit properly
            emit EncryptedBackupData(BackupData);
require(msg.sender == owner, "Caller is unauthorised, it must be the owner");

        
      }


      function setVolumeShare (Inputs calldata inputs, uint256[] calldata proof, BackupDataElement[] memory BackupData) public  {

         verify(proof, uint(FunctionNames.setVolumeShare), inputs);

            // this seems silly (it is) but its the only way to get the event to emit properly
            emit EncryptedBackupData(BackupData);
require(msg.sender == owner, "Caller is unauthorised, it must be the owner");

        
      }


      function setSequenceNumberInterval (Inputs calldata inputs, uint256[] calldata proof, BackupDataElement[] memory BackupData) public  {

         verify(proof, uint(FunctionNames.setSequenceNumberInterval), inputs);

            // this seems silly (it is) but its the only way to get the event to emit properly
            emit EncryptedBackupData(BackupData);
require(msg.sender == owner, "Caller is unauthorised, it must be the owner");

        
      }


      function initSequenceNumber (Inputs calldata inputs, uint256[] calldata proof, BackupDataElement[] memory BackupData) public  {

         verify(proof, uint(FunctionNames.initSequenceNumber), inputs);

            // this seems silly (it is) but its the only way to get the event to emit properly
            emit EncryptedBackupData(BackupData);
require(msg.sender == owner, "Caller is unauthorised, it must be the owner");

        
      }


      function initSurplusSequenceNumber (Inputs calldata inputs, uint256[] calldata proof, BackupDataElement[] memory BackupData) public  {

         verify(proof, uint(FunctionNames.initSurplusSequenceNumber), inputs);

            // this seems silly (it is) but its the only way to get the event to emit properly
            emit EncryptedBackupData(BackupData);
require(msg.sender == owner, "Caller is unauthorised, it must be the owner");

        
      }


      function setInitialContractParams (Inputs calldata inputs, uint256[] calldata proof, BackupDataElement[] memory BackupData) public  {

         verify(proof, uint(FunctionNames.setInitialContractParams), inputs);

            // this seems silly (it is) but its the only way to get the event to emit properly
            emit EncryptedBackupData(BackupData);

require(isContractTerminated == false);












        
      }
}