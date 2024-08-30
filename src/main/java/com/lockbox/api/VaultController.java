package com.lockbox.api;

import com.lockbox.model.Vault;
import com.lockbox.service.VaultService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/vaults")
public class VaultController {
    @Autowired
    private VaultService vaultService;

    @GetMapping
    public List<Vault> getAllVaults() {
        return vaultService.getAllVaults();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Vault> getVaultById(@PathVariable String id) {
        return vaultService.getVaultById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/user/{userId}")
    public List<Vault> getVaultsByUserId(@PathVariable String userId) {
        return vaultService.getVaultsByUserId(userId);
    }

    @PostMapping
    public Vault createVault(@RequestBody Vault vault) {
        return vaultService.createVault(vault);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Vault> updateVault(@PathVariable String id, @RequestBody Vault vaultDetails) {
        return ResponseEntity.ok(vaultService.updateVault(id, vaultDetails));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteVault(@PathVariable String id) {
        vaultService.deleteVault(id);
        return ResponseEntity.noContent().build();
    }
}
