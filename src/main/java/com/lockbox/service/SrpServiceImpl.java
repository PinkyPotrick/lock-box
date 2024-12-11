package com.lockbox.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.dto.RegisterResponseDTO;
import com.lockbox.dto.SrpParamsDTO;
import com.lockbox.dto.SrpParamsRequestDTO;
import com.lockbox.dto.SrpParamsResponseDTO;
import com.lockbox.dto.UserLoginDTO;
import com.lockbox.dto.UserLoginRequestDTO;
import com.lockbox.dto.UserLoginResponseDTO;
import com.lockbox.dto.UserRegistrationDTO;
import com.lockbox.dto.mappers.EncryptedDataAesCbcMapper;
import com.lockbox.model.EncryptedDataAesCbc;
import com.lockbox.model.User;
import com.lockbox.repository.UserRepository;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.EncryptionUtils;
import com.lockbox.utils.SrpUtils;

import jakarta.servlet.http.HttpSession;

import java.math.BigInteger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

@Service
public class SrpServiceImpl implements SrpService {

    @Autowired
    private TokenService tokenService;

    @Autowired
    private UserService userService;

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    @Autowired
    private GenericEncryptionServiceImpl genericEncryptionService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private HttpSession httpSession;

    /**
     * TODO write javadoc for the 'registerUser' function
     * 
     * @param userRegistration
     * @return
     * @throws Exception
     */
    @Override
    public RegisterResponseDTO registerUser(UserRegistrationDTO userRegistration) throws Exception {
        // Decrypt the received data

        // Create the registered user and generate a session token
        User user = userService.createUser(userRegistration);
        String sessionToken = tokenService.generateToken(user);

        // Create the response with the encrypted session token of the client
        KeyGenerator keyGen = KeyGenerator.getInstance(AppConstants.AES_CYPHER);
        keyGen.init(AppConstants.AES_256);
        SecretKey aesKey = keyGen.generateKey();
        EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
        // UserProfileMapper userProfileMapper = new UserProfileMapper();
        RegisterResponseDTO registerResponse = new RegisterResponseDTO();
        // UserProfileDTO userProfileDTO = new UserProfileDTO();
        EncryptedDataAesCbc encryptedSessionToken = EncryptionUtils.encryptWithAESCBC(sessionToken, aesKey);
        registerResponse.setEncryptedSessionToken(encryptedDataAesCbcMapper.toDto(encryptedSessionToken));
        registerResponse.setHelperAesKey(encryptedSessionToken.getAesKeyBase64());

        return registerResponse;
    }

    /**
     * Initiates the SRP (Secure Remote Password) handshake process by generating the server's public value (B) and the
     * salt.
     * 
     * This method corresponds to the first step of the SRP protocol, where the server sends its public value (B) and a
     * unique salt to the client. The client uses these values, along with its own private value (A), to compute a
     * shared secret that will be used for further authentication steps.
     * 
     * @param encryprtedSrpParams - The SRP parameters received from the client, including the client's public value (A)
     *                            and username.
     * @return A {@link SrpParamsResponseDTO} containing the server's public value (B) and the salt, to be sent back to
     *         the client.
     * @throws Exception
     */
    @Override
    public SrpParamsResponseDTO initiateSrpHandshake(SrpParamsRequestDTO encryprtedSrpParams) throws Exception {
        // Decrypt the received encrypted DTO data
        SrpParamsDTO srpParamsDTO = decryptSrpParamsRequestDTO(encryprtedSrpParams);

        // Retrieve user information
        User user = userRepository.findByUsername(srpParamsDTO.getDerivedUsername());
        if (user == null) {
            throw new RuntimeException(AppConstants.AuthenticationErrors.INVALID_CREDENTIALS);
        }
        BigInteger userVerifier = new BigInteger(user.getVerifier(), 16);

        // Decrypt the encrypted salt from the DB
        String salt = genericEncryptionService.decryptDTOWithRSA(user.getSalt(), String.class);

        // Compute SRP variables
        BigInteger serverPrivateValueB = SrpUtils.generateRandomPrivateValue();
        BigInteger serverPublicValueB = SrpUtils.computeB(userVerifier, serverPrivateValueB);

        // Store temporary user values in session
        httpSession.setAttribute(AppConstants.HttpSessionAttributes.CLIENT_PUBLIC_VALUE_A,
                srpParamsDTO.getClientPublicValueA());
        httpSession.setAttribute(AppConstants.HttpSessionAttributes.SERVER_PUBLIC_VALUE_B, serverPublicValueB);
        httpSession.setAttribute(AppConstants.HttpSessionAttributes.SERVER_PRIVATE_VALUE_B, serverPrivateValueB);
        httpSession.setAttribute(AppConstants.HttpSessionAttributes.DERIVED_USERNAME,
                srpParamsDTO.getDerivedUsername());
        httpSession.setAttribute(AppConstants.HttpSessionAttributes.CLIENT_PUBLIC_KEY,
                srpParamsDTO.getClientPublicKey());

        // Create the response with the encrypted data
        SrpParamsResponseDTO srpParamsResponse = encryptSrpParamsResponseDTO(serverPublicValueB, salt);
        return srpParamsResponse;
    }

    /**
     * Verifies the client's proof (M1) and completes the SRP (Secure Remote Password) authentication process.
     * 
     * This method handles the second phase of the SRP protocol, where the server verifies the client's proof of the
     * shared secret (M1). If the verification is successful, the server computes its own proof (M2) and generates a
     * session token for the authenticated client. These values are then returned to the client to complete the mutual
     * authentication process.
     * 
     * @param encryptedUserLogin - The login data received from the client, typically including the client's public
     *                           value (A), proof (M1), and username.
     * @return A {@link UserLoginResponseDTO} containing the server's proof (M2) and the session token, to be sent back
     *         to the client.
     * @throws Exception
     */
    @Override
    public UserLoginResponseDTO verifyClientProofAndAuthenticate(UserLoginRequestDTO encryptedUserLogin)
            throws Exception {
        // Decrypt the received data
        UserLoginDTO userLoginDTO = decryptUserLoginRequestDTO(encryptedUserLogin);

        // Retrieve session data and user information
        BigInteger clientPublicValueA = (BigInteger) httpSession
                .getAttribute(AppConstants.HttpSessionAttributes.CLIENT_PUBLIC_VALUE_A);
        BigInteger serverPublicValueB = (BigInteger) httpSession
                .getAttribute(AppConstants.HttpSessionAttributes.SERVER_PUBLIC_VALUE_B);
        BigInteger serverPrivateValueB = (BigInteger) httpSession
                .getAttribute(AppConstants.HttpSessionAttributes.SERVER_PRIVATE_VALUE_B);
        String derivedUsername = (String) httpSession.getAttribute(AppConstants.HttpSessionAttributes.DERIVED_USERNAME);
        String clientPublicKey = (String) httpSession
                .getAttribute(AppConstants.HttpSessionAttributes.CLIENT_PUBLIC_KEY);

        // Abort if A % N == 0
        if (clientPublicValueA.mod(AppConstants.N).equals(BigInteger.ZERO)) {
            throw new RuntimeException(AppConstants.AuthenticationErrors.INVALID_CLIENT_VALUE_A);
        }

        // Retrieve user information
        User user = userRepository.findByUsername(derivedUsername);
        if (user == null || clientPublicValueA == null || serverPublicValueB == null || serverPrivateValueB == null) {
            throw new RuntimeException(AppConstants.AuthenticationErrors.INVALID_SESSION);
        }
        BigInteger userVerifier = new BigInteger(user.getVerifier(), 16);

        // The salt needs to be decrypted first
        String salt = rsaKeyPairService.decryptRSAWithServerPrivateKey(user.getSalt());

        // Compute SRP variables
        BigInteger scramblingParameterU = SrpUtils.computeU(serverPublicValueB);
        BigInteger sharedSecretS = SrpUtils.computeS(clientPublicValueA, userVerifier, scramblingParameterU,
                serverPrivateValueB);
        String sessionKeyK = SrpUtils.computeK(sharedSecretS);
        String serverProofM1 = SrpUtils.computeM1(derivedUsername, salt, clientPublicValueA, serverPublicValueB,
                sessionKeyK);

        // Compare the client's M1 with the server's M1, if the values are equal then
        // both the client and server share the same secret
        if (!serverProofM1.equals(userLoginDTO.getEclientProofM1())) {
            throw new RuntimeException(AppConstants.AuthenticationErrors.INVALID_PROOF);
        }

        // Compute server proof and generate session token
        String serverProofM2 = SrpUtils.computeM2(clientPublicValueA, serverProofM1, sessionKeyK);
        String sessionToken = tokenService.generateToken(user);

        // Clear session attributes after successful authentication
        httpSession.invalidate();

        // Create the response with the encrypted data
        UserLoginResponseDTO userLoginResponse = encryptUserLoginResponseDTO(user.getPublicKey(), user.getPrivateKey(),
                sessionToken, serverProofM2, clientPublicKey);
        return userLoginResponse;
    }

    /**
     * Decrypts the SRP parameters received from the client on frontend.
     * 
     * @param encryprtedSrpParams - The encrypted SRP parameters received from the client, including the client's public
     *                            value (A) and username.
     * @return A {@link SrpParamsDTO} containing the decrypted SRP parameters.
     * @throws Exception
     */
    private SrpParamsDTO decryptSrpParamsRequestDTO(SrpParamsRequestDTO encryprtedSrpParams) throws Exception {
        String derivedUsername = genericEncryptionService
                .decryptDTOWithRSA(encryprtedSrpParams.getEncryptedDerivedUsername(), String.class);
        String clientPublicKey = genericEncryptionService.decryptDTOWithAESCBC(
                encryprtedSrpParams.getEncryptedClientPublicKey(), String.class, encryprtedSrpParams.getHelperAesKey());
        BigInteger clientPublicValueA = genericEncryptionService.decryptDTOWithAESCBC(
                encryprtedSrpParams.getEncryptedClientPublicValueA(), BigInteger.class,
                encryprtedSrpParams.getHelperAesKey());

        SrpParamsDTO srpParamsDTO = new SrpParamsDTO();
        srpParamsDTO.setDerivedUsername(derivedUsername);
        srpParamsDTO.setClientPublicKey(clientPublicKey);
        srpParamsDTO.setClientPublicValueA(clientPublicValueA);

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
    private SrpParamsResponseDTO encryptSrpParamsResponseDTO(BigInteger serverPublicValueB, String salt)
            throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(AppConstants.AES_CYPHER);
        keyGen.init(AppConstants.AES_256);
        SecretKey aesKey = keyGen.generateKey();
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
    private UserLoginDTO decryptUserLoginRequestDTO(UserLoginRequestDTO encryptedUserLogin) throws Exception {
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
    private UserLoginResponseDTO encryptUserLoginResponseDTO(String userPublicKey, String userPrivateKey,
            String sessionToken, String serverProofM2, String clientPublicKey) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(AppConstants.AES_CYPHER);
        keyGen.init(AppConstants.AES_256);
        SecretKey aesKey = keyGen.generateKey();
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
