package com.lockbox.service;

import java.math.BigInteger;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.dto.SrpParamsDTO;
import com.lockbox.dto.SrpParamsRequestDTO;
import com.lockbox.dto.SrpParamsResponseDTO;
import com.lockbox.dto.UserLoginDTO;
import com.lockbox.dto.UserLoginRequestDTO;
import com.lockbox.dto.UserLoginResponseDTO;
import com.lockbox.dto.UserRegistrationDTO;
import com.lockbox.dto.UserRegistrationRequestDTO;
import com.lockbox.dto.UserRegistrationResponseDTO;
import com.lockbox.dto.mappers.EncryptedDataAesCbcMapper;
import com.lockbox.model.EncryptedDataAesCbc;
import com.lockbox.utils.EncryptionUtils;

@Service
public class SrpEncryptionServiceImpl implements SrpEncryptionService {

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
     * @param encryprtedSrpParams - The encrypted SRP parameters received from the client, including the client's public
     *                            value (A) and username.
     * @return A {@link SrpParamsDTO} containing the decrypted SRP parameters.
     * @throws Exception
     */
    @Override
    public SrpParamsDTO decryptSrpParamsRequestDTO(SrpParamsRequestDTO encryprtedSrpParams) throws Exception {
        String derivedUsername = genericEncryptionService
                .decryptDTOWithRSA(encryprtedSrpParams.getEncryptedDerivedUsername(), String.class);
        String clientPublicKey = genericEncryptionService.decryptDTOWithAESCBC(
                encryprtedSrpParams.getEncryptedClientPublicKey(), String.class, encryprtedSrpParams.getHelperAesKey());
        BigInteger clientPublicValueA = genericEncryptionService.decryptDTOWithAESCBC(
                encryprtedSrpParams.getEncryptedClientPublicValueA(), BigInteger.class,
                encryprtedSrpParams.getHelperAesKey());
        String derivedKey = genericEncryptionService.decryptDTOWithRSA(encryprtedSrpParams.getDerivedKey(),
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
        String clientProofM = genericEncryptionService.decryptDTOWithRSA(encryptedUserLogin.getEncryptedClientProofM1(),
                String.class);

        UserLoginDTO userLoginDTO = new UserLoginDTO();
        userLoginDTO.setEclientProofM1(clientProofM);

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
}
