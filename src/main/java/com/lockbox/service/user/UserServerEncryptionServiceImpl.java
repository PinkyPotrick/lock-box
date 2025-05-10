package com.lockbox.service.user;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.lockbox.model.User;
import com.lockbox.service.encryption.GenericEncryptionService;
import com.lockbox.service.encryption.RSAKeyPairService;
import com.lockbox.utils.EncryptionUtils;

/**
 * Implementation of the {@link UserServerEncryptionService} interface. Provides methods to encrypt and decrypt User
 * data for secure storage in the database. Uses a combination of RSA and AES encryption to secure sensitive user data.
 */
@Component
public class UserServerEncryptionServiceImpl implements UserServerEncryptionService {

	@Autowired
	private GenericEncryptionService genericEncryptionService;

	@Autowired
	private RSAKeyPairService rsaKeyPairService;

	/**
	 * Encrypts sensitive {@link User} data before storing in the database. Uses the user's public key to encrypt
	 * personal data (email, salt, verifier, created date) and server's public key to encrypt the AES key used for
	 * public/private key encryption.
	 * 
	 * @param user - The user with plaintext data to be encrypted
	 * @return {@link User} object with sensitive fields encrypted
	 * @throws Exception If the encryption process fails
	 */
	@Override
	public User encryptServerData(User user) throws Exception {
		User encryptedUser = new User();
		String serverPublicKeyPem = rsaKeyPairService.getPublicKeyInPEM(rsaKeyPairService.getPublicKey());
		SecretKey aesKey = EncryptionUtils.generateAESKey();
		String userPublicKeyPem = user.getPublicKey();

		// Copy non-encrypted fields
		encryptedUser.setId(user.getId());
		encryptedUser.setUsername(user.getUsername());

		// Encrypt sensitive fields
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

	/**
	 * Decrypts encrypted {@link User} data after retrieving from the database. First decrypts the AES key with the
	 * server's private key, then uses it to decrypt the user's private key, which is then used to decrypt all other
	 * user data.
	 * 
	 * @param user - The user with encrypted data to be decrypted
	 * @return {@link User} object with decrypted sensitive fields
	 * @throws Exception If the decryption process fails
	 */
	@Override
	public User decryptServerData(User user) throws Exception {
		User decryptedUser = new User();
		String aesKeyString = rsaKeyPairService.decryptRSAWithServerPrivateKey(user.getAesKey());
		SecretKey aesKey = EncryptionUtils.getAESKeyFromString(aesKeyString);
		String decryptedUserPrivateKey = genericEncryptionService.decryptStringWithAESCBC(user.getPrivateKey(), aesKey);

		// Copy non-encrypted fields
		decryptedUser.setId(user.getId());
		decryptedUser.setUsername(user.getUsername());

		// Decrypt sensitive fields
		decryptedUser.setEmail(
				genericEncryptionService.decryptDTOWithRSA(user.getEmail(), String.class, decryptedUserPrivateKey));
		decryptedUser.setSalt(
				genericEncryptionService.decryptDTOWithRSA(user.getSalt(), String.class, decryptedUserPrivateKey));
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
