package com.lockbox.service;

import com.lockbox.repository.CredentialRepository;
import com.lockbox.blockchain.Blockchain;
import com.lockbox.model.Credential;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
public class CredentialService {

    @Autowired
    private CredentialRepository passwordRepository;

    private Blockchain blockchain;

    public CredentialService() {
        this.blockchain = new Blockchain();
    }

    public List<Credential> getAllCredentials() {
        return passwordRepository.findAll();
    }

    public Credential getCredentialById(String id) {
        return passwordRepository.getReferenceById(id);
    }

    public Credential createCredential(Credential password) {
        password.setId(UUID.randomUUID().toString());
        //this.blockchain.addBlock(password.getCredential()); <--- Check here how to use blockchain, we need to configure it with the repository
        return passwordRepository.save(password);
    }

    public Credential updateCredential(String id, Credential newCredential) {
        Credential password = passwordRepository.getReferenceById(id);
        
        password.setPassword(newCredential.getPassword());
        password.setUsername(newCredential.getUsername());
        password.setWebsite(newCredential.getWebsite());

        return passwordRepository.save(password);
    }

    public Credential saveCredential(Credential password) {
        return passwordRepository.save(password);
    }

    public void deleteCredential(String id) {
        passwordRepository.deleteById(id);
    }

    public boolean isBlockchainValid() {
        return this.blockchain.isChainValid();
    }
}
