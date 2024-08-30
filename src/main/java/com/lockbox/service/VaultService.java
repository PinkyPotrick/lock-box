package com.lockbox.service;

import com.lockbox.model.Vault;
import com.lockbox.repository.VaultRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class VaultService {
    @Autowired
    private VaultRepository vaultRepository;

    public List<Vault> getAllVaults() {
        return vaultRepository.findAll();
    }

    public Optional<Vault> getVaultById(String id) {
        return vaultRepository.findById(id);
    }

    public List<Vault> getVaultsByUserId(String userId) {
        return vaultRepository.findByUserId(userId);
    }

    public Vault createVault(Vault vault) {
        vault.setId(UUID.randomUUID().toString());
        return vaultRepository.save(vault);
    }

    public Vault updateVault(String id, Vault vaultDetails) {
        Vault vault = vaultRepository.findById(id).orElseThrow(() -> new RuntimeException("Vault not found"));
        vault.setName(vaultDetails.getName());
        return vaultRepository.save(vault);
    }

    public void deleteVault(String id) {
        vaultRepository.deleteById(id);
    }
}
