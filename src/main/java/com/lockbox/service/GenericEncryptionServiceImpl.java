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
     * Decrypts a string using AES-CBC with a provided secret key.
     *
     * @param string    - The encrypted string to decrypt
     * @param secretKey - The secret key used for decryption
     * @return The decrypted string
     * @throws Exception if the decryption process fails
     */
    @Override
    public String decryptStringWithAESCBC(String string, SecretKey secretKey) throws Exception {
        return EncryptionUtils.decryptStringWithAESCBC(string, secretKey);
    }

    /**
     * Encrypts a string using AES-CBC with a provided secret key.
     *
     * @param string    - The string to encrypt
     * @param secretKey - The secret key used for encryption
     * @return The encrypted string
     * @throws Exception if the encryption process fails
     */
    @Override
    public String encryptStringWithAESCBC(String string, SecretKey secretKey) throws Exception {
        return EncryptionUtils.encryptStringWithAESCBC(string, secretKey);
    }

    /**
     * Decrypts a given DTO using RSA encryption and converts it to the specified target type.
     *
     * @param <T>           - The type of the input DTO.
     * @param <R>           - The type of the output object.
     * @param dto           - The DTO to be decrypted. It can be a raw JSON string or an object.
     * @param targetType    - The class type of the target object to which the decrypted JSON should be converted.
     * @param privateKeyPem - The private key in PEM format used for decryption. If null, the server's private key will
     *                      be used.
     * @return The decrypted object of the specified target type.
     * @throws Exception If an error occurs during decryption or JSON processing.
     */
    @Override
    public <T, R> R decryptDTOWithRSA(T dto, Class<R> targetType, String privateKeyPem) throws Exception {
        String json, decryptedJson;

        // Handle raw DTO types
        if (dto instanceof String string) {
            json = string;
        } else {
            json = objectMapper.writeValueAsString(dto);
        }

        // If the private key is null, use the server's private key for decryption
        if (privateKeyPem == null) {
            decryptedJson = rsaKeyPairService.decryptRSAWithServerPrivateKey(json);
        } else {
            decryptedJson = rsaKeyPairService.decryptRSAWithPrivateKey(json, privateKeyPem);
        }

        if (targetType.equals(String.class)) {
            return targetType.cast(decryptedJson);
        }

        return objectMapper.readValue(decryptedJson, targetType);
    }

    /**
     * Decrypts a given DTO using RSA encryption and converts it to the specified target type. This method uses the
     * server's private key for decryption.
     *
     * @param <T>        - The type of the input DTO.
     * @param <R>        - The type of the output object.
     * @param dto        - The DTO to be decrypted. It can be a raw JSON string or an object.
     * @param targetType - The class type of the target object to which the decrypted JSON should be converted.
     * @return The decrypted object of the specified target type.
     * @throws Exception If an error occurs during decryption or JSON processing.
     * @see #decryptDTOWithRSA(Object, Class, String)
     */
    @Override
    public <T, R> R decryptDTOWithRSA(T dto, Class<R> targetType) throws Exception {
        return decryptDTOWithRSA(dto, targetType, null);
    }

    /**
     * Encrypts a given DTO using RSA encryption and converts it to the specified target type.
     *
     * @param <T>          - The type of the input DTO.
     * @param <R>          - The type of the output object.
     * @param dto          - The DTO to be encrypted. It can be a raw JSON string or an object.
     * @param targetType   - The class type of the target object to which the encrypted JSON should be converted.
     * @param publicKeyPem - The public key in PEM format used for encryption. If null, the server's public key will be
     *                     used.
     * @return The encrypted object of the specified target type.
     * @throws Exception If an error occurs during encryption or JSON processing.
     */
    @Override
    public <T, R> R encryptDTOWithRSA(T dto, Class<R> targetType, String publicKeyPem) throws Exception {
        String json, encryptedJson;

        // Handle raw DTO types
        if (dto instanceof String string) {
            json = string;
        } else {
            json = objectMapper.writeValueAsString(dto);
        }

        // If the private key is null, use the server's public key for decryption
        if (publicKeyPem == null) {
            encryptedJson = rsaKeyPairService.encryptRSAWithServerPublicKey(json);
        } else {
            encryptedJson = rsaKeyPairService.encryptRSAWithPublicKey(json, publicKeyPem);
        }

        if (targetType.equals(String.class)) {
            return targetType.cast(encryptedJson);
        }

        return objectMapper.readValue(encryptedJson, targetType);
    }

    /**
     * Encrypts a given DTO using RSA encryption and converts it to the specified target type. This method uses the
     * server's public key for encryption.
     *
     * @param <T>        - The type of the input DTO.
     * @param <R>        - The type of the output object.
     * @param dto        - The DTO to be encrypted. It can be a raw JSON string or an object.
     * @param targetType - The class type of the target object to which the encrypted JSON should be converted.
     * @return The encrypted object of the specified target type.
     * @throws Exception If an error occurs during encryption or JSON processing.
     * @see #encryptDTOWithRSA(Object, Class, String)
     */
    @Override
    public <T, R> R encryptDTOWithRSA(T dto, Class<R> targetType) throws Exception {
        return encryptDTOWithRSA(dto, targetType, null);
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
        if (dto instanceof String string) {
            json = string;
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
