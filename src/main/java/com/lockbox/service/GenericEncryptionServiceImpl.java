package com.lockbox.service;

import java.math.BigInteger;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lockbox.model.EncryptedDataAesCbc;
import com.lockbox.utils.EncryptionUtils;

@Service
public class GenericEncryptionServiceImpl implements GenericEncryptionService {

    // The following ObjectMapper is used for JSON conversion
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    /**
     * Decrypts a DTO using RSA and the server's private key into a target class type.
     *
     * @param dto       - The encrypted DTO to decrypt
     * @param classType - The type of the DTO to be returned after decryption
     * @return The decrypted data mapped to the target class type
     * @throws Exception if the decryption process fails
     */
    @Override
    public <T, R> R decryptDTOWithRSA(T dto, Class<R> targetType) throws Exception {
        String json;

        // Handle raw DTO types
        if (dto instanceof String) {
            json = (String) dto;
        } else {
            json = objectMapper.writeValueAsString(dto);
        }

        String decryptedJson = rsaKeyPairService.decryptRSAWithServerPrivateKey(json);

        if (targetType.equals(String.class)) {
            return targetType.cast(decryptedJson);
        }

        return objectMapper.readValue(decryptedJson, targetType);
    }

    /**
     * Encrypts a DTO using RSA and a provided public key into a target class type.
     *
     * @param dto          - The DTO to encrypt
     * @param classType    - The type of the DTO to be returned after encryption
     * @param publicKeyPem - The public key in PEM format used for encryption
     * @return The encrypted data mapped to the target class type
     * @throws Exception if the encryption process fails
     */
    @Override
    public <T, R> R encryptDTOWithRSA(T dto, Class<R> targetType, String publicKeyPem) throws Exception {
        String json;

        // Handle raw DTO types
        if (dto instanceof String) {
            json = (String) dto;
        } else {
            json = objectMapper.writeValueAsString(dto);
        }

        String encryptedJson = rsaKeyPairService.encryptRSAWithPublicKey(json, publicKeyPem);

        if (targetType.equals(String.class)) {
            return targetType.cast(encryptedJson);
        }

        return objectMapper.readValue(encryptedJson, targetType);
    }

    /**
     * Decrypts a DTO using AES-CBC with the provided AES key into a target class type.
     *
     * @param dto          - The encrypted DTO to decrypt
     * @param classType    - The type of the DTO to be returned after decryption
     * @param aesKeyBase64 - The Base64-encoded AES key for decryption
     * @return The decrypted data mapped to the target class type
     * @throws Exception if the decryption process fails, such as HMAC verification failure
     */
    @Override
    public <T, R> R decryptDTOWithAESCBC(T dto, Class<R> targetType, String aesKeyBase64) throws Exception {
        String json = objectMapper.writeValueAsString(dto);
        EncryptedDataAesCbc payload = objectMapper.readValue(json, EncryptedDataAesCbc.class);
        String decryptedJson = EncryptionUtils.decryptWithAESCBC(payload.getEncryptedDataBase64(),
                payload.getIvBase64(), payload.getHmacBase64(), aesKeyBase64);

        // Handle raw target types
        if (targetType.equals(String.class) || targetType.equals(BigInteger.class)) {
            if (targetType.equals(String.class)) {
                return targetType.cast(decryptedJson);
            }
            if (targetType.equals(BigInteger.class)) {
                return targetType.cast(new BigInteger(decryptedJson, 16));
            }
        }

        return objectMapper.readValue(decryptedJson, targetType);
    }

    /**
     * Encrypts a DTO using AES-CBC with the provided AES key into a target class type.
     *
     * @param dto       - The DTO to encrypt
     * @param classType - The type of the DTO to be returned after encryption
     * @param aesKey    - The AES secret key for encryption
     * @return The encrypted data mapped to the target class type
     * @throws Exception if the encryption process fails
     */
    @Override
    public <T, R> R encryptDTOWithAESCBC(T dto, Class<R> targetType, SecretKey aesKey) throws Exception {
        String json;

        // Handle raw DTO types
        if (dto instanceof String) {
            json = (String) dto;
        } else {
            json = objectMapper.writeValueAsString(dto);
        }

        EncryptedDataAesCbc encryptedPayload = EncryptionUtils.encryptWithAESCBC(json, aesKey);
        String encryptedPayloadJson = objectMapper.writeValueAsString(encryptedPayload);

        if (targetType.equals(String.class)) {
            return targetType.cast(encryptedPayloadJson);
        }

        return objectMapper.readValue(encryptedPayloadJson, targetType);
    }
}
