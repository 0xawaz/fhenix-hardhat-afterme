// SPDX-License-Identifier: MIT

pragma solidity >=0.8.13 <0.9.0;

import "@fhenixprotocol/contracts/FHE.sol";
import {Permissioned, Permission} from "@fhenixprotocol/contracts/access/Permissioned.sol";

contract AfterMe is Permissioned {
    // Encrypted master password field
    bytes private encryptedMasterPassword;

    // Address of the owner
    address public owner;

    // Constructor initializes the owner
    constructor() {
        owner = msg.sender;
    }

    // Function to set the encrypted master password
    function setMasterPassword(bytes calldata encryptedPassword) public {
        // Only the owner can set the master password
        require(msg.sender == owner, "Not authorized");
        encryptedMasterPassword = encryptedPassword;
    }

    // Function to get the encrypted master password
    function getMasterPassword() public view returns (bytes memory) {
        // Decrypt the password using FHE (Fully Homomorphic Encryption)
        return FHE.decrypt(encryptedMasterPassword);
    }

    // Function to get the encrypted master password with permissions
    function getMasterPasswordPermit(
        Permission memory permission
    ) public view onlySender(permission) returns (bytes memory) {
        // Decrypt the password using FHE with permissions
        return FHE.decrypt(encryptedMasterPassword);
    }

    // Function to get the encrypted master password sealed with permissions
    function getMasterPasswordPermitSealed(
        Permission memory permission
    ) public view onlySender(permission) returns (string memory) {
        // Seal the encrypted password for secure transfer with permissions
        return FHE.sealoutput(encryptedMasterPassword, permission.publicKey);
    }
}
