package com.lockbox.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.lockbox.model.User;

@Component
public class UserServerEncryptionService {

    @Autowired
    private GenericEncryptionService genericEncryptionService;

    // public User decryptClientData(final UserRegistrationRequestDTO userRegistration) throws Exception {
    // String derivedKey = rsaKeyPairService.decryptRSAWithServerPrivateKey(userRegistration.getDerivedKey());
    // String firstDecryptionUsername = rsaKeyPairService
    // .decryptRSAWithServerPrivateKey(userRegistration.getEncryptedDerivedUsername());
    // String username = EncryptionUtils.decryptUsername(firstDecryptionUsername, derivedKey);
    // String email = rsaKeyPairService.decryptRSAWithServerPrivateKey(userRegistration.getEncryptedEmail());
    // String salt = rsaKeyPairService.decryptRSAWithServerPrivateKey(userRegistration.getEncryptedSalt());

    // EncryptedDataAesCbcDTO encryptedVerifier = userRegistration.getEncryptedClientVerifier();
    // if (encryptedVerifier != null) {
    // String fullyDecryptedVerifier = EncryptionUtils.decryptWithAESCBC(
    // encryptedVerifier.getEncryptedDataBase64(), encryptedVerifier.getIvBase64(),
    // encryptedVerifier.getHmacBase64(), userRegistration.getHelperAesKey());
    // }

    // UserRegistrationMapper userRegistrationMapper = new UserRegistrationMapper();
    // User user = userRegistrationMapper.fromDto(userRegistration);

    // user.setId(UUID.randomUUID().toString());
    // user.setCreatedAt(rsaKeyPairService.encryptRSAWithPublicKey(
    // LocalDate.now().format(DateTimeFormatter.ISO_LOCAL_DATE), user.getPublicKey()));
    // user.setUsername(
    // rsaKeyPairService.decryptRSAWithServerPrivateKey(userRegistration.getEncryptedDerivedUsername()));

    // return user;
    // }

    // public User encryptClientData(final UserRegistrationRequestDTO userRegistration) throws Exception {
    // return null;
    // }

    public User encryptServerData(User user) throws Exception {
        String publicKey = user.getPublicKey();
        User encryptedUser = new User();

        encryptedUser
                .setUsername(genericEncryptionService.encryptDTOWithRSA(user.getUsername(), String.class, publicKey));
        encryptedUser.setEmail(genericEncryptionService.encryptDTOWithRSA(user.getEmail(), String.class, publicKey));
        encryptedUser.setSalt(genericEncryptionService.encryptDTOWithRSA(user.getSalt(), String.class, publicKey));
        encryptedUser
                .setVerifier(genericEncryptionService.encryptDTOWithRSA(user.getVerifier(), String.class, publicKey));
        encryptedUser
                .setPublicKey(genericEncryptionService.encryptDTOWithRSA(user.getPublicKey(), String.class, publicKey));
        encryptedUser.setPrivateKey(
                genericEncryptionService.encryptDTOWithRSA(user.getPrivateKey(), String.class, publicKey));
        encryptedUser
                .setCreatedAt(genericEncryptionService.encryptDTOWithRSA(user.getCreatedAt(), String.class, publicKey));

        return encryptedUser;
    }

    public User decryptServerData(User user) throws Exception {
        User decryptedUser = new User();

        decryptedUser.setUsername(genericEncryptionService.decryptDTOWithRSA(user.getUsername(), String.class));
        decryptedUser.setEmail(genericEncryptionService.decryptDTOWithRSA(user.getEmail(), String.class));
        decryptedUser.setSalt(genericEncryptionService.decryptDTOWithRSA(user.getSalt(), String.class));
        decryptedUser.setVerifier(genericEncryptionService.decryptDTOWithRSA(user.getVerifier(), String.class));
        decryptedUser.setPublicKey(genericEncryptionService.decryptDTOWithRSA(user.getPublicKey(), String.class));
        decryptedUser.setPrivateKey(genericEncryptionService.decryptDTOWithRSA(user.getPrivateKey(), String.class));
        decryptedUser.setCreatedAt(genericEncryptionService.decryptDTOWithRSA(user.getCreatedAt(), String.class));

        return decryptedUser;
    }
}
