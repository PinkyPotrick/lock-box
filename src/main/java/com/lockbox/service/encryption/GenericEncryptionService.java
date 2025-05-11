package com.lockbox.service.encryption;

import javax.crypto.SecretKey;

public interface GenericEncryptionService {

    public String decryptStringWithAESCBC(String string, SecretKey secretKey) throws Exception;

    public String encryptStringWithAESCBC(String string, SecretKey secretKey) throws Exception;

    public <T, R> R decryptDTOWithRSA(T dto, Class<R> targetType, String privateKeyPem) throws Exception;

    public <T, R> R decryptDTOWithRSA(T dto, Class<R> targetType) throws Exception;

    public <T, R> R encryptDTOWithRSA(T dto, Class<R> targetType, String publicKeyPem) throws Exception;

    public <T, R> R encryptDTOWithRSA(T dto, Class<R> targetType) throws Exception;

    public <T, R> R decryptDTOWithAESCBC(T dto, Class<R> targetType, String aesKeyBase64) throws Exception;

    public <T, R> R encryptDTOWithAESCBC(T dto, Class<R> targetType, SecretKey aesKey) throws Exception;
}
