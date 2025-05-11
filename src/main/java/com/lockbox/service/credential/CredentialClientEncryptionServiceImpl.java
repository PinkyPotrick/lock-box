package com.lockbox.service.credential;

import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.dto.credential.CredentialDTO;
import com.lockbox.dto.credential.CredentialListResponseDTO;
import com.lockbox.dto.credential.CredentialRequestDTO;
import com.lockbox.dto.credential.CredentialResponseDTO;
import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;
import com.lockbox.dto.encryption.EncryptedDataAesCbcMapper;
import com.lockbox.model.EncryptedDataAesCbc;
import com.lockbox.service.encryption.GenericEncryptionService;
import com.lockbox.utils.EncryptionUtils;

/**
 * Implementation of the {@link CredentialClientEncryptionService} interface. Provides methods for encrypting and
 * decrypting credential data for secure transmission between client and server.
 */
@Service
public class CredentialClientEncryptionServiceImpl implements CredentialClientEncryptionService {

    @Autowired
    private GenericEncryptionService genericEncryptionService;

    /**
     * Encrypts a credential DTO for client response. Uses AES encryption to secure the credential data.
     * 
     * @param credentialDTO - The credential data to encrypt
     * @return Encrypted {@link CredentialResponseDTO} ready for transmission to client
     * @throws Exception If encryption fails
     */
    @Override
    public CredentialResponseDTO encryptCredentialForClient(CredentialDTO credentialDTO) throws Exception {
        if (credentialDTO == null) {
            return null;
        }

        // Generate a helper AES key
        SecretKey aesKey = EncryptionUtils.generateAESKey();
        EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
        CredentialResponseDTO responseDTO = new CredentialResponseDTO();

        // Encrypt required fields with the helper AES key
        EncryptedDataAesCbc encryptedUsername = genericEncryptionService
                .encryptDTOWithAESCBC(credentialDTO.getUsername(), EncryptedDataAesCbc.class, aesKey);

        EncryptedDataAesCbc encryptedPassword = genericEncryptionService
                .encryptDTOWithAESCBC(credentialDTO.getPassword(), EncryptedDataAesCbc.class, aesKey);

        // Encrypt optional fields only if they exist
        EncryptedDataAesCbc encryptedEmail = null;
        if (credentialDTO.getEmail() != null) {
            encryptedEmail = genericEncryptionService.encryptDTOWithAESCBC(credentialDTO.getEmail(),
                    EncryptedDataAesCbc.class, aesKey);
        }

        EncryptedDataAesCbc encryptedNotes = null;
        if (credentialDTO.getNotes() != null) {
            encryptedNotes = genericEncryptionService.encryptDTOWithAESCBC(credentialDTO.getNotes(),
                    EncryptedDataAesCbc.class, aesKey);
        }

        EncryptedDataAesCbc encryptedCategory = null;
        if (credentialDTO.getCategory() != null) {
            encryptedCategory = genericEncryptionService.encryptDTOWithAESCBC(credentialDTO.getCategory(),
                    EncryptedDataAesCbc.class, aesKey);
        }

        EncryptedDataAesCbc encryptedFavorite = null;
        encryptedFavorite = genericEncryptionService.encryptDTOWithAESCBC(credentialDTO.isFavorite(),
                EncryptedDataAesCbc.class, aesKey);

        // Set basic field values that don't need encryption
        responseDTO.setId(credentialDTO.getId());
        responseDTO.setUserId(credentialDTO.getUserId());
        responseDTO.setVaultId(credentialDTO.getVaultId());
        responseDTO.setDomainId(credentialDTO.getDomainId());
        responseDTO.setCreatedAt(credentialDTO.getCreatedAt());
        responseDTO.setUpdatedAt(credentialDTO.getUpdatedAt());
        responseDTO.setLastUsed(credentialDTO.getLastUsed());

        // Set encrypted data fields
        responseDTO.setEncryptedUsername(encryptedDataAesCbcMapper.toDto(encryptedUsername));
        responseDTO.setEncryptedPassword(encryptedDataAesCbcMapper.toDto(encryptedPassword));

        if (encryptedEmail != null) {
            responseDTO.setEncryptedEmail(encryptedDataAesCbcMapper.toDto(encryptedEmail));
        }

        if (encryptedNotes != null) {
            responseDTO.setEncryptedNotes(encryptedDataAesCbcMapper.toDto(encryptedNotes));
        }

        if (encryptedCategory != null) {
            responseDTO.setEncryptedCategory(encryptedDataAesCbcMapper.toDto(encryptedCategory));
        }

        if (encryptedFavorite != null) {
            responseDTO.setEncryptedFavorite(encryptedDataAesCbcMapper.toDto(encryptedFavorite));
        }

        // Set the helper AES key
        responseDTO.setHelperAesKey(encryptedUsername.getAesKeyBase64());

        return responseDTO;
    }

    /**
     * Encrypts a list of credential DTOs for client response with vault name.
     * 
     * @param credentialDTOs - The list of credential data to encrypt
     * @param vaultName - The vault name to encrypt
     * @return {@link CredentialListResponseDTO} containing encrypted credentials ready for transmission
     * @throws Exception If encryption fails
     */
    @Override
    public CredentialListResponseDTO encryptCredentialListForClient(List<CredentialDTO> credentialDTOs, String vaultName) 
            throws Exception {
        if (credentialDTOs == null) {
            return null;
        }

        // Generate a helper AES key for vault name encryption
        SecretKey aesKey = EncryptionUtils.generateAESKey();
        String aesKeyBase64 = EncryptionUtils.getAESKeyString(aesKey);
        
        List<CredentialResponseDTO> encryptedCredentials = new ArrayList<>();
        for (CredentialDTO credentialDTO : credentialDTOs) {
            encryptedCredentials.add(encryptCredentialForClient(credentialDTO));
        }
        
        // Encrypt the vault name
        EncryptedDataAesCbcDTO encryptedVaultName = null;
        if (vaultName != null) {
            encryptedVaultName = encryptVaultName(vaultName, aesKeyBase64);
        }
        
        return new CredentialListResponseDTO(encryptedCredentials, credentialDTOs.size(), 
                encryptedVaultName, aesKeyBase64);
    }
    
    /**
     * Encrypts a vault name for client response.
     * 
     * @param vaultName - The vault name to encrypt
     * @param aesKeyBase64 - The AES key to use for encryption (base64 encoded)
     * @return {@link EncryptedDataAesCbcDTO} containing encrypted vault name
     * @throws Exception If encryption fails
     */
    @Override
    public EncryptedDataAesCbcDTO encryptVaultName(String vaultName, String aesKeyBase64) throws Exception {
        if (vaultName == null) {
            return null;
        }
        
        SecretKey aesKey = EncryptionUtils.getAESKeyFromString(aesKeyBase64);
        EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
        
        EncryptedDataAesCbc encryptedVaultNameData = genericEncryptionService
                .encryptDTOWithAESCBC(vaultName, EncryptedDataAesCbc.class, aesKey);
                
        return encryptedDataAesCbcMapper.toDto(encryptedVaultNameData);
    }

    /**
     * Decrypts a credential request DTO from the client.
     * 
     * @param requestDTO - The encrypted credential request from client
     * @return Decrypted {@link CredentialDTO}
     * @throws Exception If decryption fails
     */
    @Override
    public CredentialDTO decryptCredentialFromClient(CredentialRequestDTO requestDTO) throws Exception {
        if (requestDTO == null || requestDTO.getEncryptedUsername() == null || requestDTO.getEncryptedPassword() == null
                || requestDTO.getHelperAesKey() == null) {
            return null;
        }

        // Decrypt required fields
        String username = genericEncryptionService.decryptDTOWithAESCBC(requestDTO.getEncryptedUsername(), String.class,
                requestDTO.getHelperAesKey());

        String password = genericEncryptionService.decryptDTOWithAESCBC(requestDTO.getEncryptedPassword(), String.class,
                requestDTO.getHelperAesKey());

        // Decrypt optional fields if present
        String email = null;
        if (requestDTO.getEncryptedEmail() != null) {
            email = genericEncryptionService.decryptDTOWithAESCBC(requestDTO.getEncryptedEmail(), String.class,
                    requestDTO.getHelperAesKey());
        }

        String notes = null;
        if (requestDTO.getEncryptedNotes() != null) {
            notes = genericEncryptionService.decryptDTOWithAESCBC(requestDTO.getEncryptedNotes(), String.class,
                    requestDTO.getHelperAesKey());
        }

        String category = null;
        if (requestDTO.getEncryptedCategory() != null) {
            category = genericEncryptionService.decryptDTOWithAESCBC(requestDTO.getEncryptedCategory(), String.class,
                    requestDTO.getHelperAesKey());
        }

        Boolean favorite = null;
        if (requestDTO.getEncryptedFavorite() != null) {
            String favoriteStr = genericEncryptionService.decryptDTOWithAESCBC(requestDTO.getEncryptedFavorite(),
                    String.class, requestDTO.getHelperAesKey());
            favorite = Boolean.parseBoolean(favoriteStr);
        }

        // Create and populate the DTO with decrypted values
        CredentialDTO credentialDTO = new CredentialDTO();
        credentialDTO.setUsername(username);
        credentialDTO.setPassword(password);
        credentialDTO.setEmail(email);
        credentialDTO.setNotes(notes);
        credentialDTO.setCategory(category);
        credentialDTO.setFavorite(favorite != null ? favorite : false);

        // Copy non-encrypted fields from request
        if (requestDTO.getVaultId() != null) {
            credentialDTO.setVaultId(requestDTO.getVaultId());
        }

        if (requestDTO.getDomainId() != null) {
            credentialDTO.setDomainId(requestDTO.getDomainId());
        }

        return credentialDTO;
    }
}