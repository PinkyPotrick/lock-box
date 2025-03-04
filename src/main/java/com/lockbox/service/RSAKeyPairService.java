package com.lockbox.service;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface RSAKeyPairService {

    void init();

    PublicKey getPublicKey();

    PrivateKey getPrivateKey();

    String getPublicKeyInPEM(PublicKey publicKey);

    String encryptRSAWithServerPublicKey(String decryptedData);

    String decryptRSAWithServerPrivateKey(String encryptedData);

    String encryptRSAWithPublicKey(String decryptedData, String publicKeyPem);

    String decryptRSAWithPrivateKey(String encryptedData, String privateKeyPem);
}