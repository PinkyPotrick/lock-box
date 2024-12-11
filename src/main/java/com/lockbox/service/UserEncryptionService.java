package com.lockbox.service;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;

import com.lockbox.dto.EncryptedDataAesCbcDTO;
import com.lockbox.dto.UserRegistrationDTO;
import com.lockbox.dto.mappers.UserRegistrationMapper;
import com.lockbox.model.User;
import com.lockbox.utils.EncryptionUtils;

public class UserEncryptionService {

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    public User decryptClientData(final UserRegistrationDTO userRegistration) throws Exception {
        String derivedKey = rsaKeyPairService.decryptRSAWithServerPrivateKey(userRegistration.getDerivedKey());
        String firstDecryptionUsername = rsaKeyPairService.decryptRSAWithServerPrivateKey(userRegistration.getUsername());
        String username = EncryptionUtils.decryptUsername(firstDecryptionUsername, derivedKey);
        String email = rsaKeyPairService.decryptRSAWithServerPrivateKey(userRegistration.getEmail());
        String salt = rsaKeyPairService.decryptRSAWithServerPrivateKey(userRegistration.getSalt());

        EncryptedDataAesCbcDTO encryptedVerifier = userRegistration.getEncryptedClientVerifier();
        if (encryptedVerifier != null) {
            String fullyDecryptedVerifier = EncryptionUtils.decryptWithAESCBC(
                    encryptedVerifier.getEncryptedDataBase64(), encryptedVerifier.getIvBase64(),
                    encryptedVerifier.getHmacBase64(), userRegistration.getHelperAesKey());
        }

        UserRegistrationMapper userRegistrationMapper = new UserRegistrationMapper();
        User user = userRegistrationMapper.fromDto(userRegistration);
        
        user.setId(UUID.randomUUID().toString());
        user.setCreatedAt(rsaKeyPairService
                .encryptRSAWithPublicKey(LocalDate.now().format(DateTimeFormatter.ISO_LOCAL_DATE), user.getPublicKey()));
        user.setUsername(rsaKeyPairService.decryptRSAWithServerPrivateKey(userRegistration.getUsername()));

        return user;
    }

    public User encryptClientData(final UserRegistrationDTO userRegistration) throws Exception {
        return null;
    }

    public User encryptServerData() throws Exception {
        return null;
    }

    public User decryptServerData() throws Exception {
        return null;
    }
}
