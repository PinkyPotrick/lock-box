package com.lockbox.service.vault;

import java.util.Optional;

import com.lockbox.dto.vault.VaultListResponseDTO;
import com.lockbox.dto.vault.VaultRequestDTO;
import com.lockbox.dto.vault.VaultResponseDTO;
import com.lockbox.model.Vault;

public interface VaultService {

    VaultListResponseDTO findAllVaultsByUser(String userId, Integer page, Integer size) throws Exception;

    VaultResponseDTO findVaultById(String id, String userId) throws Exception;

    VaultResponseDTO createVault(VaultRequestDTO requestDTO, String userId) throws Exception;

    VaultResponseDTO updateVault(String id, VaultRequestDTO requestDTO, String userId) throws Exception;

    void deleteVault(String id, String userId) throws Exception;

    boolean isVaultOwnedByUser(String vaultId, String userId) throws Exception;

    Optional<Vault> findById(String id) throws Exception;

    int countByUserId(String userId);
}