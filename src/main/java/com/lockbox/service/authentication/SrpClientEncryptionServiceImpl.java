package com.lockbox.service.authentication;

import java.math.BigInteger;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.dto.authentication.login.UserLoginDTO;
import com.lockbox.dto.authentication.login.UserLoginRequestDTO;
import com.lockbox.dto.authentication.login.UserLoginResponseDTO;
import com.lockbox.dto.authentication.password.PasswordChangeCompleteRequestDTO;
import com.lockbox.dto.authentication.password.PasswordChangeCompleteResponseDTO;
import com.lockbox.dto.authentication.password.PasswordChangeCredentialsDTO;
import com.lockbox.dto.authentication.password.PasswordChangeInitDTO;
import com.lockbox.dto.authentication.password.PasswordChangeInitRequestDTO;
import com.lockbox.dto.authentication.password.PasswordChangeInitResponseDTO;
import com.lockbox.dto.authentication.registration.UserRegistrationDTO;
import com.lockbox.dto.authentication.registration.UserRegistrationRequestDTO;
import com.lockbox.dto.authentication.registration.UserRegistrationResponseDTO;
import com.lockbox.dto.authentication.srp.SrpParamsDTO;
import com.lockbox.dto.authentication.srp.SrpParamsRequestDTO;
import com.lockbox.dto.authentication.srp.SrpParamsResponseDTO;
import com.lockbox.dto.encryption.EncryptedDataAesCbcMapper;
import com.lockbox.model.EncryptedDataAesCbc;
import com.lockbox.model.User;
import com.lockbox.service.encryption.GenericEncryptionServiceImpl;
import com.lockbox.utils.EncryptionUtils;

/**
 * Implementation of the {@link SrpClientEncryptionService} interface, responsible for encrypting and decrypting
 * authentication-related data using SRP (Secure Remote Password) protocol.
 */
@Service
public class SrpClientEncryptionServiceImpl implements SrpClientEncryptionService {

    @Autowired
    private GenericEncryptionServiceImpl genericEncryptionService;

    /**
     * Decrypts the user registration data received from the client on frontend.
     * 
     * @param encryptedUserRegistration - The encrypted user registration data received from the client, including the
     *                                  derived key, username, email, salt, client's verifier, public key and private
     *                                  key.
     * @return A {@link UserRegistrationDTO} containing the decrypted user registration data.
     * @throws Exception
     */
    @Override
    public UserRegistrationDTO decryptUserRegistrationRequestDTO(UserRegistrationRequestDTO encryptedUserRegistration)
            throws Exception {

        String derivedUsername = genericEncryptionService
                .decryptDTOWithRSA(encryptedUserRegistration.getEncryptedDerivedUsername(), String.class);
        String email = genericEncryptionService.decryptDTOWithRSA(encryptedUserRegistration.getEncryptedEmail(),
                String.class);
        String salt = genericEncryptionService.decryptDTOWithRSA(encryptedUserRegistration.getEncryptedSalt(),
                String.class);
        String clientVerifier = genericEncryptionService.decryptDTOWithAESCBC(
                encryptedUserRegistration.getEncryptedClientVerifier(), String.class,
                encryptedUserRegistration.getHelperAesKey());
        String clientPublicKey = genericEncryptionService.decryptDTOWithAESCBC(
                encryptedUserRegistration.getEncryptedClientPublicKey(), String.class,
                encryptedUserRegistration.getHelperAesKey());
        String clientPrivateKey = genericEncryptionService.decryptDTOWithAESCBC(
                encryptedUserRegistration.getEncryptedClientPrivateKey(), String.class,
                encryptedUserRegistration.getHelperAesKey());
        String derivedKey = genericEncryptionService.decryptDTOWithRSA(encryptedUserRegistration.getDerivedKey(),
                String.class);

        UserRegistrationDTO userRegistrationDTO = new UserRegistrationDTO();
        userRegistrationDTO.setDerivedUsername(derivedUsername);
        userRegistrationDTO.setEmail(email);
        userRegistrationDTO.setSalt(salt);
        userRegistrationDTO.setClientVerifier(clientVerifier);
        userRegistrationDTO.setClientPublicKey(clientPublicKey);
        userRegistrationDTO.setClientPrivateKey(clientPrivateKey);
        userRegistrationDTO.setDerivedKey(derivedKey);

        return userRegistrationDTO;
    }

    /**
     * Encrypts the user registration data to be sent to the client on frontend.
     * 
     * @param sessionToken - the currently generated active session token of the authenticated user.
     * @return A {@link UserRegistrationResponseDTO} containing the encrypted session token, to be sent back to the
     *         client.
     * @throws Exception
     */
    @Override
    public UserRegistrationResponseDTO encryptUserRegistrationResponseDTO(String sessionToken) throws Exception {
        SecretKey aesKey = EncryptionUtils.generateAESKey();
        EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
        UserRegistrationResponseDTO userRegistrationResponse = new UserRegistrationResponseDTO();
        EncryptedDataAesCbc encryptedSessionToken = EncryptionUtils.encryptWithAESCBC(sessionToken, aesKey);
        userRegistrationResponse.setEncryptedSessionToken(encryptedDataAesCbcMapper.toDto(encryptedSessionToken));
        userRegistrationResponse.setHelperAesKey(encryptedSessionToken.getAesKeyBase64());

        return userRegistrationResponse;
    }

    /**
     * Decrypts the SRP parameters received from the client on frontend.
     * 
     * @param encryptedSrpParams - The encrypted SRP parameters received from the client, including the client's public
     *                           value (A) and username.
     * @return A {@link SrpParamsDTO} containing the decrypted SRP parameters.
     * @throws Exception
     */
    @Override
    public SrpParamsDTO decryptSrpParamsRequestDTO(SrpParamsRequestDTO encryptedSrpParams) throws Exception {
        String derivedUsername = genericEncryptionService
                .decryptDTOWithRSA(encryptedSrpParams.getEncryptedDerivedUsername(), String.class);
        String clientPublicKey = genericEncryptionService.decryptDTOWithAESCBC(
                encryptedSrpParams.getEncryptedClientPublicKey(), String.class, encryptedSrpParams.getHelperAesKey());
        BigInteger clientPublicValueA = genericEncryptionService.decryptDTOWithAESCBC(
                encryptedSrpParams.getEncryptedClientPublicValueA(), BigInteger.class,
                encryptedSrpParams.getHelperAesKey());
        String derivedKey = genericEncryptionService.decryptDTOWithRSA(encryptedSrpParams.getDerivedKey(),
                String.class);

        SrpParamsDTO srpParamsDTO = new SrpParamsDTO();
        srpParamsDTO.setDerivedUsername(derivedUsername);
        srpParamsDTO.setClientPublicKey(clientPublicKey);
        srpParamsDTO.setClientPublicValueA(clientPublicValueA);
        srpParamsDTO.setDerivedKey(derivedKey);

        return srpParamsDTO;
    }

    /**
     * Encrypts the SRP parameters to be sent to the client on frontend.
     * 
     * @param serverPublicValueB - the public value (B) of the server.
     * @param salt               - the unique salt of the user.
     * @return A {@link SrpParamsResponseDTO} containing the encrypted server's public value (B) and the salt, to be
     *         sent back to the client.
     * @throws Exception
     */
    @Override
    public SrpParamsResponseDTO encryptSrpParamsResponseDTO(BigInteger serverPublicValueB, String salt)
            throws Exception {
        SecretKey aesKey = EncryptionUtils.generateAESKey();
        EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
        SrpParamsResponseDTO srpParamsResponse = new SrpParamsResponseDTO();
        EncryptedDataAesCbc encryptedServerPublicValueB = genericEncryptionService
                .encryptDTOWithAESCBC(serverPublicValueB.toString(16), EncryptedDataAesCbc.class, aesKey);
        srpParamsResponse.setEncryptedServerPublicValueB(encryptedDataAesCbcMapper.toDto(encryptedServerPublicValueB));
        srpParamsResponse.setHelperSrpParamsAesKey(encryptedServerPublicValueB.getAesKeyBase64());
        srpParamsResponse.setSalt(salt);

        return srpParamsResponse;
    }

    /**
     * Decrypts the user login data received from the client on frontend.
     * 
     * @param encryptedUserLogin - The encrypted login data received from the client, typically including the client's
     *                           public value (A), proof (M1), and username.
     * @return A {@link UserLoginDTO} containing the decrypted login data.
     * @throws Exception
     */
    @Override
    public UserLoginDTO decryptUserLoginRequestDTO(UserLoginRequestDTO encryptedUserLogin) throws Exception {
        String clientProofM1 = genericEncryptionService
                .decryptDTOWithRSA(encryptedUserLogin.getEncryptedClientProofM1(), String.class);

        UserLoginDTO userLoginDTO = new UserLoginDTO();
        userLoginDTO.setEclientProofM1(clientProofM1);

        return userLoginDTO;
    }

    /**
     * Encrypts the user login data to be sent to the client on frontend.
     * 
     * @param userPublicKey   - the public key of the user.
     * @param userPrivateKey  - the private key of the user.
     * @param sessionToken    - the currently generated active session token of the authenticated user.
     * @param serverProofM2   - the calculated server proof (M2).
     * @param clientPublicKey - the public key of the client.
     * @return A {@link UserLoginResponseDTO} containing the encrypted server's proof (M2) and the session token, to be
     *         sent back to the client.
     * @throws Exception
     */
    @Override
    public UserLoginResponseDTO encryptUserLoginResponseDTO(String userPublicKey, String userPrivateKey,
            String sessionToken, String serverProofM2, String clientPublicKey) throws Exception {
        SecretKey aesKey = EncryptionUtils.generateAESKey();
        EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
        UserLoginResponseDTO userLoginResponse = new UserLoginResponseDTO();
        EncryptedDataAesCbc encryptedClientPublicKey = genericEncryptionService.encryptDTOWithAESCBC(userPublicKey,
                EncryptedDataAesCbc.class, aesKey);
        EncryptedDataAesCbc encryptedClientPrivateKey = genericEncryptionService.encryptDTOWithAESCBC(userPrivateKey,
                EncryptedDataAesCbc.class, aesKey);
        EncryptedDataAesCbc encryptedSessionToken = genericEncryptionService.encryptDTOWithAESCBC(sessionToken,
                EncryptedDataAesCbc.class, aesKey);
        String encryptedServerProofM2 = genericEncryptionService.encryptDTOWithRSA(serverProofM2, String.class,
                clientPublicKey);
        userLoginResponse.setEncryptedUserPublicKey(encryptedDataAesCbcMapper.toDto(encryptedClientPublicKey));
        userLoginResponse.setEncryptedUserPrivateKey(encryptedDataAesCbcMapper.toDto(encryptedClientPrivateKey));
        userLoginResponse.setEncryptedSessionToken(encryptedDataAesCbcMapper.toDto(encryptedSessionToken));
        userLoginResponse.setEncryptedServerProofM2(encryptedServerProofM2);
        userLoginResponse.setHelperAuthenticateAesKey(encryptedSessionToken.getAesKeyBase64());

        return userLoginResponse;
    }

    /**
     * Decrypts the password change initialization data received from the client on frontend.
     * 
     * @param passwordChangeInitRequest - The encrypted password change initialization data received from the client,
     *                                  including the derived key, encrypted derived username, and encrypted client's
     *                                  public value (A).
     * @return A {@link PasswordChangeInitDTO} containing the decrypted password change initialization data.
     * @throws Exception If decryption fails
     */
    @Override
    public PasswordChangeInitDTO decryptPasswordChangeInitRequestDTO(
            PasswordChangeInitRequestDTO passwordChangeInitRequest) throws Exception {
        String derivedUsername = genericEncryptionService
                .decryptDTOWithRSA(passwordChangeInitRequest.getEncryptedDerivedUsername(), String.class);
        BigInteger clientPublicValueA = genericEncryptionService.decryptDTOWithAESCBC(
                passwordChangeInitRequest.getEncryptedClientPublicValueA(), BigInteger.class,
                passwordChangeInitRequest.getHelperAesKey());
        String derivedKey = genericEncryptionService.decryptDTOWithRSA(passwordChangeInitRequest.getDerivedKey(),
                String.class);

        PasswordChangeInitDTO passwordChangeInitDTO = new PasswordChangeInitDTO();
        passwordChangeInitDTO.setDerivedUsername(derivedUsername);
        passwordChangeInitDTO.setClientPublicValueA(clientPublicValueA);
        passwordChangeInitDTO.setDerivedKey(derivedKey);

        return passwordChangeInitDTO;
    }

    /**
     * Encrypts the password change initialization response data to be sent to the client on frontend.
     * 
     * @param serverPublicValueB - the public value (B) of the server for password change verification.
     * @param salt               - the unique salt of the user's current password.
     * @return A {@link PasswordChangeInitResponseDTO} containing the encrypted server's public value (B) and the salt,
     *         to be sent back to the client.
     * @throws Exception If encryption fails
     */
    @Override
    public PasswordChangeInitResponseDTO encryptPasswordChangeInitResponseDTO(BigInteger serverPublicValueB,
            String salt) throws Exception {
        SecretKey aesKey = EncryptionUtils.generateAESKey();
        EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
        PasswordChangeInitResponseDTO responseDTO = new PasswordChangeInitResponseDTO();

        // Encrypt the server's public value B
        EncryptedDataAesCbc encryptedServerPublicValueB = genericEncryptionService
                .encryptDTOWithAESCBC(serverPublicValueB.toString(16), EncryptedDataAesCbc.class, aesKey);

        responseDTO.setEncryptedServerPublicValueB(encryptedDataAesCbcMapper.toDto(encryptedServerPublicValueB));
        responseDTO.setHelperAesKey(encryptedServerPublicValueB.getAesKeyBase64());
        responseDTO.setSalt(salt); // Salt is sent in plaintext as in the SRP protocol

        return responseDTO;
    }

    /**
     * Decrypts the client proof and new credentials from the password change completion request.
     * 
     * @param passwordChangeCompleteRequest - The encrypted request data
     * @return A DTO containing the decrypted proof and new credentials
     * @throws Exception If decryption fails
     */
    @Override
    public PasswordChangeCredentialsDTO decryptPasswordChangeCredentials(
            PasswordChangeCompleteRequestDTO passwordChangeCompleteRequest) throws Exception {

        // Decrypt the client's proof M1
        String clientProofM1 = genericEncryptionService
                .decryptDTOWithRSA(passwordChangeCompleteRequest.getEncryptedClientProofM1(), String.class);

        // Decrypt the new salt
        String newSalt = genericEncryptionService.decryptDTOWithRSA(passwordChangeCompleteRequest.getEncryptedNewSalt(),
                String.class);

        // Decrypt the new derived key
        String newDerivedKey = genericEncryptionService
                .decryptDTOWithRSA(passwordChangeCompleteRequest.getEncryptedNewDerivedKey(), String.class);

        // Decrypt the new derived username
        String newDerivedUsername = genericEncryptionService
                .decryptDTOWithRSA(passwordChangeCompleteRequest.getEncryptedNewDerivedUsername(), String.class);

        // Decrypt the new verifier
        String newVerifier = genericEncryptionService.decryptDTOWithAESCBC(
                passwordChangeCompleteRequest.getEncryptedNewVerifier(), String.class,
                passwordChangeCompleteRequest.getHelperAesKey());

        PasswordChangeCredentialsDTO credentials = new PasswordChangeCredentialsDTO();
        credentials.setClientProofM1(clientProofM1);
        credentials.setNewSalt(newSalt);
        credentials.setNewDerivedKey(newDerivedKey);
        credentials.setNewDerivedUsername(newDerivedUsername);
        credentials.setNewVerifier(newVerifier);

        return credentials;
    }

    /**
     * Encrypts the server proof and success status for password change response.
     * 
     * @param serverProofM2 - The server's proof (M2) confirming successful verification.
     * @param success       - Whether the password change was successfully processed.
     * @return An encrypted {@link PasswordChangeCompleteResponseDTO} containing the server's proof and success status.
     * @throws Exception If encryption fails
     */
    @Override
    public PasswordChangeCompleteResponseDTO encryptPasswordChangeCompleteResponseDTO(String serverProofM2,
            boolean success, User user) throws Exception {
        PasswordChangeCompleteResponseDTO responseDTO = new PasswordChangeCompleteResponseDTO();
        String userPublicKeyPem = user.getPublicKey();

        // Encrypt the server's proof M2
        String encryptedServerProofM2 = genericEncryptionService.encryptDTOWithRSA(serverProofM2, String.class,
                userPublicKeyPem);

        responseDTO.setEncryptedServerProofM2(encryptedServerProofM2);
        responseDTO.setSuccess(success);

        return responseDTO;
    }
}
