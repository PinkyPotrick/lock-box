package com.lockbox.api;

import com.lockbox.model.Credential;
import com.lockbox.service.CredentialService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/credentials")
public class CredentialController {

    @Autowired
    private CredentialService credentialService;

    @GetMapping
    public List<Credential> getAllCredentials() {
        return credentialService.getAllCredentials();
    }

    @GetMapping("/{id}")
    public Credential getCredentialById(@PathVariable String id) {
        return credentialService.getCredentialById(id);
    }

    @PostMapping
    public Credential createCredential(@RequestBody Credential password) {
        return credentialService.createCredential(password);
    }

    @PutMapping("/{id}")
    public Credential updateCredential(@PathVariable String id, @RequestBody Credential password) {
        return credentialService.updateCredential(id, password);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteCredential(@PathVariable String id) {
        credentialService.deleteCredential(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/validate")
    public boolean validateBlockchain() {
        return this.credentialService.isBlockchainValid();
    }
}
