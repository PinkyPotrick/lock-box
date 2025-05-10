package com.lockbox.service.vault;

import java.util.List;

import com.lockbox.dto.vault.VaultDTO;
import com.lockbox.dto.vault.VaultListResponseDTO;
import com.lockbox.dto.vault.VaultRequestDTO;
import com.lockbox.dto.vault.VaultResponseDTO;

public interface VaultClientEncryptionService {

    VaultResponseDTO encryptVaultForClient(VaultDTO vaultDTO) throws Exception;

    VaultListResponseDTO encryptVaultListForClient(List<VaultDTO> vaultDTOs) throws Exception;

    VaultDTO decryptVaultFromClient(VaultRequestDTO requestDTO) throws Exception;
}