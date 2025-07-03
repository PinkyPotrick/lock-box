package com.lockbox.service.domain;

import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.dto.domain.DomainDTO;
import com.lockbox.dto.domain.DomainListResponseDTO;
import com.lockbox.dto.domain.DomainRequestDTO;
import com.lockbox.dto.domain.DomainResponseDTO;
import com.lockbox.dto.encryption.EncryptedDataAesCbcMapper;
import com.lockbox.model.EncryptedDataAesCbc;
import com.lockbox.service.encryption.GenericEncryptionService;
import com.lockbox.utils.EncryptionUtils;

/**
 * Implementation of the {@link DomainClientEncryptionService} interface. Provides methods for encrypting and decrypting
 * domain data for secure transmission between client and server.
 */
@Service
public class DomainClientEncryptionServiceImpl implements DomainClientEncryptionService {

    private final Logger logger = LoggerFactory.getLogger(DomainClientEncryptionServiceImpl.class);

    @Autowired
    private GenericEncryptionService genericEncryptionService;

    /**
     * Encrypts a domain DTO for client response. Uses AES encryption to secure the domain data.
     * 
     * @param domainDTO - The domain data to encrypt
     * @return Encrypted {@link DomainResponseDTO} ready for transmission to client
     * @throws Exception If encryption fails
     */
    @Override
    public DomainResponseDTO encryptDomainForClient(DomainDTO domainDTO) throws Exception {
        if (domainDTO == null) {
            return null;
        }

        // Generate a helper AES key
        long startTime = System.currentTimeMillis();
        SecretKey aesKey = EncryptionUtils.generateAESKey();
        EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
        DomainResponseDTO responseDTO = new DomainResponseDTO();

        // Encrypt individual fields with the helper AES key
        EncryptedDataAesCbc encryptedName = genericEncryptionService.encryptDTOWithAESCBC(domainDTO.getName(),
                EncryptedDataAesCbc.class, aesKey);

        EncryptedDataAesCbc encryptedUrl = null;
        if (domainDTO.getUrl() != null) {
            encryptedUrl = genericEncryptionService.encryptDTOWithAESCBC(domainDTO.getUrl(), EncryptedDataAesCbc.class,
                    aesKey);
        }

        EncryptedDataAesCbc encryptedNotes = null;
        if (domainDTO.getNotes() != null) {
            encryptedNotes = genericEncryptionService.encryptDTOWithAESCBC(domainDTO.getNotes(),
                    EncryptedDataAesCbc.class, aesKey);
        }

        // Set basic field values that don't need encryption (for UI convenience)
        responseDTO.setId(domainDTO.getId());
        responseDTO.setUserId(domainDTO.getUserId());
        responseDTO.setLogo(domainDTO.getLogo());
        responseDTO.setCreatedAt(domainDTO.getCreatedAt());
        responseDTO.setUpdatedAt(domainDTO.getUpdatedAt());
        responseDTO.setCredentialCount(domainDTO.getCredentialCount());

        // Set encrypted data fields
        responseDTO.setEncryptedName(encryptedDataAesCbcMapper.toDto(encryptedName));

        if (encryptedUrl != null) {
            responseDTO.setEncryptedUrl(encryptedDataAesCbcMapper.toDto(encryptedUrl));
        }

        if (encryptedNotes != null) {
            responseDTO.setEncryptedNotes(encryptedDataAesCbcMapper.toDto(encryptedNotes));
        }

        responseDTO.setHelperAesKey(encryptedName.getAesKeyBase64());

        long endTime = System.currentTimeMillis();
        logger.info("Domain client encryption process completed in {} ms", endTime - startTime);

        return responseDTO;
    }

    /**
     * Encrypts a list of domain DTOs for client response.
     * 
     * @param domainDTOs - The list of domain data to encrypt
     * @return {@link DomainListResponseDTO} containing encrypted domains ready for transmission
     * @throws Exception If encryption fails
     */
    @Override
    public DomainListResponseDTO encryptDomainListForClient(List<DomainDTO> domainDTOs) throws Exception {
        if (domainDTOs == null) {
            return null;
        }

        long startTime = System.currentTimeMillis();
        List<DomainResponseDTO> encryptedDomains = new ArrayList<>();
        for (DomainDTO domainDTO : domainDTOs) {
            encryptedDomains.add(encryptDomainForClient(domainDTO));
        }

        long endTime = System.currentTimeMillis();
        logger.info("Domain list client encryption process completed in {} ms", endTime - startTime);

        return new DomainListResponseDTO(encryptedDomains, domainDTOs.size());
    }

    /**
     * Decrypts a domain request DTO from the client.
     * 
     * @param requestDTO - The encrypted domain request from client
     * @return Decrypted {@link DomainDTO}
     * @throws Exception If decryption fails
     */
    @Override
    public DomainDTO decryptDomainFromClient(DomainRequestDTO requestDTO) throws Exception {
        long startTime = System.currentTimeMillis();
        if (requestDTO == null || requestDTO.getEncryptedName() == null || requestDTO.getHelperAesKey() == null) {
            return null;
        }

        // Decrypt individual fields
        String name = genericEncryptionService.decryptDTOWithAESCBC(requestDTO.getEncryptedName(), String.class,
                requestDTO.getHelperAesKey());

        // URL might be optional, so check if it's null
        String url = null;
        if (requestDTO.getEncryptedUrl() != null) {
            url = genericEncryptionService.decryptDTOWithAESCBC(requestDTO.getEncryptedUrl(), String.class,
                    requestDTO.getHelperAesKey());
        }

        // Notes might be optional, so check if it's null
        String notes = null;
        if (requestDTO.getEncryptedNotes() != null) {
            notes = genericEncryptionService.decryptDTOWithAESCBC(requestDTO.getEncryptedNotes(), String.class,
                    requestDTO.getHelperAesKey());
        }

        // Create and populate the DTO with decrypted values
        DomainDTO domainDTO = new DomainDTO();
        domainDTO.setName(name);
        domainDTO.setUrl(url);
        domainDTO.setNotes(notes);

        // Copy non-encrypted fields from request
        if (requestDTO.getUserId() != null) {
            domainDTO.setUserId(requestDTO.getUserId());
        }

        if (requestDTO.getLogo() != null) {
            domainDTO.setLogo(requestDTO.getLogo());
        }

        long endTime = System.currentTimeMillis();
        logger.info("Domain client decryption process completed in {} ms", endTime - startTime);

        return domainDTO;
    }
}