package com.lockbox.service.vault;

import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.dto.encryption.EncryptedDataAesCbcMapper;
import com.lockbox.dto.vault.VaultDTO;
import com.lockbox.dto.vault.VaultListResponseDTO;
import com.lockbox.dto.vault.VaultRequestDTO;
import com.lockbox.dto.vault.VaultResponseDTO;
import com.lockbox.model.EncryptedDataAesCbc;
import com.lockbox.service.encryption.GenericEncryptionService;
import com.lockbox.utils.EncryptionUtils;

/**
 * Implementation of the {@link VaultClientEncryptionService} interface. Provides methods for encrypting and decrypting
 * vault data for secure transmission between client and server.
 */
@Service
public class VaultClientEncryptionServiceImpl implements VaultClientEncryptionService {

    private final Logger logger = LoggerFactory.getLogger(VaultClientEncryptionServiceImpl.class);

    @Autowired
    private GenericEncryptionService genericEncryptionService;

    /**
     * Encrypts a vault DTO for client response. Uses AES encryption to secure the vault data.
     * 
     * @param vaultDTO - The vault data to encrypt
     * @return Encrypted {@link VaultResponseDTO} ready for transmission to client
     * @throws Exception If encryption fails
     */
    @Override
    public VaultResponseDTO encryptVaultForClient(VaultDTO vaultDTO) throws Exception {
        if (vaultDTO == null) {
            return null;
        }

        // Generate a helper AES key
        long startTime = System.currentTimeMillis();
        SecretKey aesKey = EncryptionUtils.generateAESKey();
        EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
        VaultResponseDTO responseDTO = new VaultResponseDTO();

        // Encrypt individual fields with the helper AES key
        EncryptedDataAesCbc encryptedName = genericEncryptionService.encryptDTOWithAESCBC(vaultDTO.getName(),
                EncryptedDataAesCbc.class, aesKey);

        EncryptedDataAesCbc encryptedDescription = null;
        if (vaultDTO.getDescription() != null) {
            encryptedDescription = genericEncryptionService.encryptDTOWithAESCBC(vaultDTO.getDescription(),
                    EncryptedDataAesCbc.class, aesKey);
        }

        // Set basic field values that don't need encryption (for UI convenience)
        responseDTO.setId(vaultDTO.getId());
        responseDTO.setUserId(vaultDTO.getUserId());
        responseDTO.setIcon(vaultDTO.getIcon());
        responseDTO.setCreatedAt(vaultDTO.getCreatedAt());
        responseDTO.setUpdatedAt(vaultDTO.getUpdatedAt());
        responseDTO.setCredentialCount(vaultDTO.getCredentialCount());

        // Set encrypted data fields
        responseDTO.setEncryptedName(encryptedDataAesCbcMapper.toDto(encryptedName));

        if (encryptedDescription != null) {
            responseDTO.setEncryptedDescription(encryptedDataAesCbcMapper.toDto(encryptedDescription));
        }

        responseDTO.setHelperAesKey(encryptedName.getAesKeyBase64());

        long endTime = System.currentTimeMillis();
        logger.info("Vault client response encryption process completed in {} ms", endTime - startTime);

        return responseDTO;
    }

    /**
     * Encrypts a list of vault DTOs for client response.
     * 
     * @param vaultDTOs - The list of vault data to encrypt
     * @return {@link VaultListResponseDTO} containing encrypted vaults ready for transmission
     * @throws Exception If encryption fails
     */
    @Override
    public VaultListResponseDTO encryptVaultListForClient(List<VaultDTO> vaultDTOs) throws Exception {
        if (vaultDTOs == null) {
            return null;
        }

        long startTime = System.currentTimeMillis();
        List<VaultResponseDTO> encryptedVaults = new ArrayList<>();
        for (VaultDTO vaultDTO : vaultDTOs) {
            encryptedVaults.add(encryptVaultForClient(vaultDTO));
        }

        long endTime = System.currentTimeMillis();
        logger.info("Vault client list encryption process completed in {} ms", endTime - startTime);

        return new VaultListResponseDTO(encryptedVaults, vaultDTOs.size());
    }

    /**
     * Decrypts a vault request DTO from the client.
     * 
     * @param requestDTO - The encrypted vault request from client
     * @return Decrypted {@link VaultDTO}
     * @throws Exception If decryption fails
     */
    @Override
    public VaultDTO decryptVaultFromClient(VaultRequestDTO requestDTO) throws Exception {
        long startTime = System.currentTimeMillis();

        if (requestDTO == null || requestDTO.getEncryptedName() == null || requestDTO.getHelperAesKey() == null) {
            return null;
        }

        // Decrypt individual fields similar to SrpClientEncryptionServiceImpl
        String name = genericEncryptionService.decryptDTOWithAESCBC(requestDTO.getEncryptedName(), String.class,
                requestDTO.getHelperAesKey());

        // Description might be optional, so check if it's null
        String description = null;
        if (requestDTO.getEncryptedDescription() != null) {
            description = genericEncryptionService.decryptDTOWithAESCBC(requestDTO.getEncryptedDescription(),
                    String.class, requestDTO.getHelperAesKey());
        }

        // Create and populate the DTO with decrypted values
        VaultDTO vaultDTO = new VaultDTO();
        vaultDTO.setName(name);
        vaultDTO.setDescription(description);

        // Copy non-encrypted fields from request
        if (requestDTO.getUserId() != null) {
            vaultDTO.setUserId(requestDTO.getUserId());
        }

        if (requestDTO.getIcon() != null) {
            vaultDTO.setIcon(requestDTO.getIcon());
        }

        long endTime = System.currentTimeMillis();
        logger.info("Vault client decryption process completed in {} ms", endTime - startTime);

        return vaultDTO;
    }
}