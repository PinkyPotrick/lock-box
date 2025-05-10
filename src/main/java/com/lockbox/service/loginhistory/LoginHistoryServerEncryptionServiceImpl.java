package com.lockbox.service.loginhistory;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.lockbox.model.LoginHistory;
import com.lockbox.service.encryption.GenericEncryptionService;
import com.lockbox.service.encryption.RSAKeyPairService;
import com.lockbox.utils.EncryptionUtils;

/**
 * Implementation of the {@link LoginHistoryServerEncryptionService} interface. Provides methods to encrypt and decrypt
 * {@link LoginHistory} data for secure storage in the database. Uses a combination of RSA and AES encryption to secure
 * sensitive login history data.
 */
@Component
public class LoginHistoryServerEncryptionServiceImpl implements LoginHistoryServerEncryptionService {

    @Autowired
    private GenericEncryptionService genericEncryptionService;

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    /**
     * Encrypts sensitive LoginHistory data before storing in the database. Uses the AES encryption to secure sensitive
     * data.
     * 
     * @param loginHistory - The login history with plaintext data to be encrypted
     * @return {@link LoginHistory} object with sensitive fields encrypted
     * @throws Exception If the encryption process fails
     */
    @Override
    public LoginHistory encryptServerData(LoginHistory loginHistory) throws Exception {
        // Generate an AES key for encryption
        SecretKey aesKey = EncryptionUtils.generateAESKey();
        String aesKeyString = EncryptionUtils.getAESKeyString(aesKey);

        // Get the server's public key for encrypting the AES key
        String serverPublicKeyPem = rsaKeyPairService.getPublicKeyInPEM(rsaKeyPairService.getPublicKey());

        LoginHistory encryptedLoginHistory = new LoginHistory();

        // Copy non-encrypted fields
        encryptedLoginHistory.setId(loginHistory.getId());
        encryptedLoginHistory.setUserId(loginHistory.getUserId());
        encryptedLoginHistory.setLoginTimestamp(loginHistory.getLoginTimestamp());
        encryptedLoginHistory.setDate(loginHistory.getDate());
        encryptedLoginHistory.setSuccess(loginHistory.isSuccess());
        encryptedLoginHistory.setFailureReason(loginHistory.getFailureReason());

        // Encrypt sensitive fields with AES
        if (loginHistory.getIpAddress() != null) {
            encryptedLoginHistory.setIpAddress(
                    genericEncryptionService.encryptStringWithAESCBC(loginHistory.getIpAddress(), aesKey));
        }

        if (loginHistory.getUserAgent() != null) {
            encryptedLoginHistory.setUserAgent(
                    genericEncryptionService.encryptStringWithAESCBC(loginHistory.getUserAgent(), aesKey));
        }

        // Store encrypted AES key
        encryptedLoginHistory.setAesKey(rsaKeyPairService.encryptRSAWithPublicKey(aesKeyString, serverPublicKeyPem));

        return encryptedLoginHistory;
    }

    /**
     * Decrypts encrypted {@link LoginHistory} data after retrieving from the database. First decrypts the AES key with
     * the server's private key, then uses it to decrypt sensitive data.
     * 
     * @param loginHistory - The login history with encrypted data to be decrypted
     * @return {@link LoginHistory} object with decrypted sensitive fields
     * @throws Exception If the decryption process fails
     */
    @Override
    public LoginHistory decryptServerData(LoginHistory loginHistory) throws Exception {
        LoginHistory decryptedLoginHistory = new LoginHistory();

        // Decrypt the AES key with server's private key
        String aesKeyString = rsaKeyPairService.decryptRSAWithServerPrivateKey(loginHistory.getAesKey());
        SecretKey aesKey = EncryptionUtils.getAESKeyFromString(aesKeyString);

        // Copy non-encrypted fields
        decryptedLoginHistory.setId(loginHistory.getId());
        decryptedLoginHistory.setUserId(loginHistory.getUserId());
        decryptedLoginHistory.setLoginTimestamp(loginHistory.getLoginTimestamp());
        decryptedLoginHistory.setDate(loginHistory.getDate());
        decryptedLoginHistory.setSuccess(loginHistory.isSuccess());
        decryptedLoginHistory.setFailureReason(loginHistory.getFailureReason());

        // Decrypt sensitive fields with the AES key
        if (loginHistory.getIpAddress() != null) {
            decryptedLoginHistory.setIpAddress(
                    genericEncryptionService.decryptStringWithAESCBC(loginHistory.getIpAddress(), aesKey));
        }

        if (loginHistory.getUserAgent() != null) {
            decryptedLoginHistory.setUserAgent(
                    genericEncryptionService.decryptStringWithAESCBC(loginHistory.getUserAgent(), aesKey));
        }

        // Store the decrypted AES key
        decryptedLoginHistory.setAesKey(aesKeyString);

        return decryptedLoginHistory;
    }
}