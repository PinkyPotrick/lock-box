package com.lockbox.dto.mappers;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.lockbox.dto.EncryptedDataAesCbcDTO;
import com.lockbox.dto.UserRegistrationDTO;
import com.lockbox.model.User;
import com.lockbox.utils.EncryptionUtils;

public class UserRegistrationMapper {

    public UserRegistrationDTO toDto(final User user) throws Exception {
        if (user == null) {
            return null;
        }

        UserRegistrationDTO userRegistrationDTO = new UserRegistrationDTO();
        userRegistrationDTO.setUsername(user.getUsername());
        userRegistrationDTO.setEmail(user.getEmail());
        userRegistrationDTO.setSalt(user.getSalt());

        // Data needs to be encrypted because of the big length
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // AES-256
        SecretKey aesKey = keyGen.generateKey();
        EncryptedDataAesCbcMapper encryptedDataAESCBCMapper = new EncryptedDataAesCbcMapper();
        String fullyDecryptedVerifier = user.getVerifier(); // TODO might need to decrypt it (Locally)
        String fullyDecryptedClientPublicKey = user.getPublicKey(); // TODO might need to decrypt it (Locally)
        String fullyDecryptedClientPrivateKey = user.getPrivateKey(); // TODO might need to decrypt it (Locally)

        if (fullyDecryptedVerifier != null) {
            EncryptedDataAesCbcDTO encryptedVerifier = encryptedDataAESCBCMapper.toDto(EncryptionUtils.encryptWithAESCBC(fullyDecryptedVerifier, aesKey));
            userRegistrationDTO.setEncryptedClientVerifier(encryptedVerifier);
        }
        if (fullyDecryptedClientPublicKey != null) {
            EncryptedDataAesCbcDTO encryptedPublicKey = encryptedDataAESCBCMapper.toDto(EncryptionUtils.encryptWithAESCBC(fullyDecryptedClientPublicKey, aesKey));
            userRegistrationDTO.setEncryptedClientPublicKey(encryptedPublicKey);
        }
        if (fullyDecryptedClientPrivateKey != null) {
            EncryptedDataAesCbcDTO encryptedPrivateKey = encryptedDataAESCBCMapper.toDto(EncryptionUtils.encryptWithAESCBC(fullyDecryptedClientPrivateKey, aesKey));
            userRegistrationDTO.setEncryptedClientPrivateKey(encryptedPrivateKey);
        }

        return userRegistrationDTO;
    }

    public User fromDto(final UserRegistrationDTO userRegistrationDTO) throws Exception {
        if (userRegistrationDTO == null) {
            return null;
        }

        User user = new User();
        user.setUsername(userRegistrationDTO.getUsername());
        user.setEmail(userRegistrationDTO.getEmail());
        user.setSalt(userRegistrationDTO.getSalt());

        // Data needs to be decrypted because of the big length
        EncryptedDataAesCbcDTO encryptedVerifier = userRegistrationDTO.getEncryptedClientVerifier();
        EncryptedDataAesCbcDTO encryptedPublicKey = userRegistrationDTO.getEncryptedClientPublicKey();
        EncryptedDataAesCbcDTO encryptedPrivateKey = userRegistrationDTO.getEncryptedClientPrivateKey();

        if (encryptedVerifier != null) {
            String fullyDecryptedVerifier = EncryptionUtils.decryptWithAESCBC(encryptedVerifier.getEncryptedDataBase64(), encryptedVerifier.getIvBase64(), encryptedVerifier.getHmacBase64(), userRegistrationDTO.getHelperAesKey());
            user.setVerifier(fullyDecryptedVerifier); // TODO might need to encrypt it (Locally)
        }
        if (encryptedPublicKey != null) {
            String fullyDecryptedClientPublicKey = EncryptionUtils.decryptWithAESCBC(encryptedPublicKey.getEncryptedDataBase64(), encryptedPublicKey.getIvBase64(), encryptedPublicKey.getHmacBase64(), userRegistrationDTO.getHelperAesKey());
            user.setPublicKey(fullyDecryptedClientPublicKey); // TODO might need to encrypt it (Locally)
        }
        if (encryptedPrivateKey != null) {
            String fullyDecryptedClientPrivateKey = EncryptionUtils.decryptWithAESCBC(encryptedPrivateKey.getEncryptedDataBase64(), encryptedPrivateKey.getIvBase64(), encryptedPrivateKey.getHmacBase64(), userRegistrationDTO.getHelperAesKey());
            user.setPrivateKey(fullyDecryptedClientPrivateKey); // TODO might need to encrypt it (Locally)
        }
        
        return user;
    }
}
