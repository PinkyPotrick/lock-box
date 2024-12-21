package com.lockbox.dto.mappers;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

import com.lockbox.dto.UserRegistrationDTO;
import com.lockbox.model.User;

public class UserRegistrationMapper {

    // public UserRegistrationRequestDTO toDto(final User user) throws Exception {
    //     if (user == null) {
    //         return null;
    //     }

    //     UserRegistrationRequestDTO userRegistrationDTO = new UserRegistrationRequestDTO();
    //     userRegistrationDTO.setEncryptedDerivedUsername(user.getUsername());
    //     userRegistrationDTO.setEncryptedEmail(user.getEmail());
    //     userRegistrationDTO.setEncryptedSalt(user.getSalt());

    //     // Data needs to be encrypted because of the big length
    //     KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    //     keyGen.init(256); // AES-256
    //     SecretKey aesKey = keyGen.generateKey();
    //     EncryptedDataAesCbcMapper encryptedDataAESCBCMapper = new EncryptedDataAesCbcMapper();
    //     String fullyDecryptedVerifier = user.getVerifier(); // TODO might need to decrypt it (Locally)
    //     String fullyDecryptedClientPublicKey = user.getPublicKey(); // TODO might need to decrypt it (Locally)
    //     String fullyDecryptedClientPrivateKey = user.getPrivateKey(); // TODO might need to decrypt it (Locally)

    //     if (fullyDecryptedVerifier != null) {
    //         EncryptedDataAesCbcDTO encryptedVerifier = encryptedDataAESCBCMapper.toDto(EncryptionUtils.encryptWithAESCBC(fullyDecryptedVerifier, aesKey));
    //         userRegistrationDTO.setEncryptedClientVerifier(encryptedVerifier);
    //     }
    //     if (fullyDecryptedClientPublicKey != null) {
    //         EncryptedDataAesCbcDTO encryptedPublicKey = encryptedDataAESCBCMapper.toDto(EncryptionUtils.encryptWithAESCBC(fullyDecryptedClientPublicKey, aesKey));
    //         userRegistrationDTO.setEncryptedClientPublicKey(encryptedPublicKey);
    //     }
    //     if (fullyDecryptedClientPrivateKey != null) {
    //         EncryptedDataAesCbcDTO encryptedPrivateKey = encryptedDataAESCBCMapper.toDto(EncryptionUtils.encryptWithAESCBC(fullyDecryptedClientPrivateKey, aesKey));
    //         userRegistrationDTO.setEncryptedClientPrivateKey(encryptedPrivateKey);
    //     }

    //     return userRegistrationDTO;
    // }

    public User fromDto(final UserRegistrationDTO userRegistrationDTO) throws Exception {
        if (userRegistrationDTO == null) {
            return null;
        }

        User user = new User();
        user.setId(UUID.randomUUID().toString());
        user.setUsername(userRegistrationDTO.getDerivedUsername());
        user.setEmail(userRegistrationDTO.getEmail());
        user.setSalt(userRegistrationDTO.getSalt());
        user.setVerifier(userRegistrationDTO.getClientVerifier());
        user.setPublicKey(userRegistrationDTO.getClientPublicKey());
        user.setPrivateKey(userRegistrationDTO.getClientPrivateKey());
        user.setCreatedAt(LocalDate.now().format(DateTimeFormatter.ISO_LOCAL_DATE));
        
        return user;

        // if (userRegistrationDTO == null) {
        //     return null;
        // }

        // User user = new User();
        // user.setUsername(userRegistrationDTO.getEncryptedDerivedUsername());
        // user.setEmail(userRegistrationDTO.getEncryptedEmail());
        // user.setSalt(userRegistrationDTO.getEncryptedSalt());

        // // Data needs to be decrypted because of the big length
        // EncryptedDataAesCbcDTO encryptedVerifier = userRegistrationDTO.getEncryptedClientVerifier();
        // EncryptedDataAesCbcDTO encryptedPublicKey = userRegistrationDTO.getEncryptedClientPublicKey();
        // EncryptedDataAesCbcDTO encryptedPrivateKey = userRegistrationDTO.getEncryptedClientPrivateKey();

        // if (encryptedVerifier != null) {
        //     String fullyDecryptedVerifier = EncryptionUtils.decryptWithAESCBC(encryptedVerifier.getEncryptedDataBase64(), encryptedVerifier.getIvBase64(), encryptedVerifier.getHmacBase64(), userRegistrationDTO.getHelperAesKey());
        //     user.setVerifier(fullyDecryptedVerifier); // TODO might need to encrypt it (Locally)
        // }
        // if (encryptedPublicKey != null) {
        //     String fullyDecryptedClientPublicKey = EncryptionUtils.decryptWithAESCBC(encryptedPublicKey.getEncryptedDataBase64(), encryptedPublicKey.getIvBase64(), encryptedPublicKey.getHmacBase64(), userRegistrationDTO.getHelperAesKey());
        //     user.setPublicKey(fullyDecryptedClientPublicKey); // TODO might need to encrypt it (Locally)
        // }
        // if (encryptedPrivateKey != null) {
        //     String fullyDecryptedClientPrivateKey = EncryptionUtils.decryptWithAESCBC(encryptedPrivateKey.getEncryptedDataBase64(), encryptedPrivateKey.getIvBase64(), encryptedPrivateKey.getHmacBase64(), userRegistrationDTO.getHelperAesKey());
        //     user.setPrivateKey(fullyDecryptedClientPrivateKey); // TODO might need to encrypt it (Locally)
        // }
        
        // return user;
    }
}
