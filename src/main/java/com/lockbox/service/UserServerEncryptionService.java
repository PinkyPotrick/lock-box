package com.lockbox.service;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.lockbox.model.User;
import com.lockbox.utils.EncryptionUtils;

@Component
public class UserServerEncryptionService {

	@Autowired
	private GenericEncryptionService genericEncryptionService;

	@Autowired
	private RSAKeyPairService rsaKeyPairService;

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

	public void testingEncryptionDecryption(User user) throws Exception {
		User encryptedUser = encryptServerData(user);
		User decryptedUser = decryptServerData(encryptedUser);
		System.out.println(decryptedUser);
	}

	public User encryptServerData(User user) throws Exception {
		User encryptedUser = new User();
		String serverPublicKeyPem = rsaKeyPairService.getPublicKeyInPEM(rsaKeyPairService.getPublicKey());
		SecretKey aesKey = EncryptionUtils.generateAESKey();

		// Encrypt user's data with the user's public key
		String userPublicKeyPem = user.getPublicKey();
		encryptedUser.setUsername(user.getUsername());
		encryptedUser
				.setEmail(genericEncryptionService.encryptDTOWithRSA(user.getEmail(), String.class, userPublicKeyPem));
		encryptedUser
				.setSalt(genericEncryptionService.encryptDTOWithRSA(user.getSalt(), String.class, userPublicKeyPem));
		encryptedUser.setVerifier(
				genericEncryptionService.encryptDTOWithRSA(user.getVerifier(), String.class, userPublicKeyPem));
		encryptedUser.setCreatedAt(
				genericEncryptionService.encryptDTOWithRSA(user.getCreatedAt(), String.class, userPublicKeyPem));
		encryptedUser.setPublicKey(genericEncryptionService.encryptStringWithAESCBC(user.getPublicKey(), aesKey));
		encryptedUser.setPrivateKey(genericEncryptionService.encryptStringWithAESCBC(user.getPrivateKey(), aesKey));
		encryptedUser.setAesKey(
				rsaKeyPairService.encryptRSAWithPublicKey(EncryptionUtils.getAESKeyString(aesKey), serverPublicKeyPem));

		return encryptedUser;
	}

	public User decryptServerData(User user) throws Exception {
		User decryptedUser = new User();
		String aesKeyString = rsaKeyPairService.decryptRSAWithServerPrivateKey(user.getAesKey());
		SecretKey aesKey = EncryptionUtils.getAESKeyFromString(aesKeyString);
		String decryptedUserPrivateKey = genericEncryptionService.decryptStringWithAESCBC(user.getPrivateKey(), aesKey);

		// Decrypt user's data with the user's private key
		decryptedUser.setUsername(user.getUsername());
		decryptedUser
				.setEmail(genericEncryptionService.decryptDTOWithRSA(user.getEmail(), String.class, decryptedUserPrivateKey));
		decryptedUser
				.setSalt(genericEncryptionService.decryptDTOWithRSA(user.getSalt(), String.class, decryptedUserPrivateKey));
		decryptedUser.setVerifier(
				genericEncryptionService.decryptDTOWithRSA(user.getVerifier(), String.class, decryptedUserPrivateKey));
		decryptedUser.setCreatedAt(
				genericEncryptionService.decryptDTOWithRSA(user.getCreatedAt(), String.class, decryptedUserPrivateKey));
		decryptedUser.setPublicKey(genericEncryptionService.decryptStringWithAESCBC(user.getPublicKey(), aesKey));
		decryptedUser.setPrivateKey(genericEncryptionService.decryptStringWithAESCBC(user.getPrivateKey(), aesKey));
		decryptedUser.setAesKey(aesKeyString);

		return decryptedUser;
	}
}
