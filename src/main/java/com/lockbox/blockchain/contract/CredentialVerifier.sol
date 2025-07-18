// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CredentialVerifier {
    address public owner;
    mapping(string => string) public credentialHashes;
    mapping(string => uint) public lastUpdated;

    event HashStored(string indexed credentialId, uint timestamp);
    event HashVerified(string indexed credentialId, bool matches);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    function storeCredentialHash(
        string memory credentialId,
        string memory hash
    ) public onlyOwner {
        credentialHashes[credentialId] = hash;
        lastUpdated[credentialId] = block.timestamp;
        emit HashStored(credentialId, block.timestamp);
    }

    function verifyCredentialHash(
        string memory credentialId,
        string memory hash
    ) public view returns (bool) {
        return
            keccak256(abi.encodePacked(credentialHashes[credentialId])) ==
            keccak256(abi.encodePacked(hash));
    }

    function getCredentialHash(
        string memory credentialId
    ) public view returns (string memory) {
        return credentialHashes[credentialId];
    }

    function getLastUpdated(
        string memory credentialId
    ) public view returns (uint) {
        return lastUpdated[credentialId];
    }
}
