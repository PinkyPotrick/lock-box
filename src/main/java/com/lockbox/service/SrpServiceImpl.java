package com.lockbox.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.dto.UserRegistrationResponseDTO;
import com.lockbox.dto.SrpParamsDTO;
import com.lockbox.dto.SrpParamsRequestDTO;
import com.lockbox.dto.SrpParamsResponseDTO;
import com.lockbox.dto.UserLoginDTO;
import com.lockbox.dto.UserLoginRequestDTO;
import com.lockbox.dto.UserLoginResponseDTO;
import com.lockbox.dto.UserRegistrationDTO;
import com.lockbox.dto.UserRegistrationRequestDTO;
import com.lockbox.model.User;
import com.lockbox.repository.UserRepository;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.SrpUtils;

import jakarta.servlet.http.HttpSession;

import java.math.BigInteger;

@Service
public class SrpServiceImpl implements SrpService {

    private static final Logger logger = LoggerFactory.getLogger(SrpServiceImpl.class);

    @Autowired
    private TokenService tokenService;

    @Autowired
    private UserService userService;

    @Autowired
    private SrpEncryptionService srpEncryptionService;

    @Autowired
    private UserServerEncryptionService userServerEncryptionService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private HttpSession httpSession;

    /**
     * Registers a new user by decrypting the received registration data, creating the user, and generating a session
     * token.
     *
     * This method handles the user registration process by first decrypting the received encrypted registration data.
     * It then creates a new user in the system and generates a session token for the newly registered user. Finally, it
     * returns a response containing the encrypted session token.
     *
     * @param encryptedUserRegistration - The encrypted user registration data received from the client.
     * @return A {@link UserRegistrationResponseDTO} containing the encrypted session token.
     * @throws Exception If an error occurs during decryption, user creation, or token generation.
     */
    @Override
    public UserRegistrationResponseDTO registerUser(UserRegistrationRequestDTO encryptedUserRegistration)
            throws Exception {
        // Decrypt the received data
        UserRegistrationDTO userRegistrationDTO = srpEncryptionService
                .decryptUserRegistrationRequestDTO(encryptedUserRegistration);
        logger.info("Registering new user: {}", userRegistrationDTO.getDerivedUsername());

        // Create the registered user and generate a session token
        User user = userService.createUser(userRegistrationDTO);
        String sessionToken = tokenService.generateToken(user);

        // Create the response with the encrypted data
        UserRegistrationResponseDTO userRegistrationResponse = srpEncryptionService
                .encryptUserRegistrationResponseDTO(sessionToken);

        logger.info("User registered successfully: {}", userRegistrationDTO.getDerivedUsername());
        return userRegistrationResponse;
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
     * @throws Exception If an error occurs during decryption, user retrieval, or SRP computation.
     */
    @Override
    public SrpParamsResponseDTO initiateSrpHandshake(SrpParamsRequestDTO encryprtedSrpParams) throws Exception {
        // Decrypt the received encrypted DTO data
        SrpParamsDTO srpParamsDTO = srpEncryptionService.decryptSrpParamsRequestDTO(encryprtedSrpParams);
        logger.info("SRP handshake initiated for user: {}", srpParamsDTO.getDerivedUsername());

        // Retrieve the user information and decrypt the user data
        User encryptedUser = userRepository.findByUsername(srpParamsDTO.getDerivedUsername());
        if (encryptedUser == null) {
            logger.warn("Authentication attempt for non-existent user: {}", srpParamsDTO.getDerivedUsername());
            throw new RuntimeException(AppConstants.AuthenticationErrors.INVALID_CREDENTIALS);
        }
        User decryptedUser = userServerEncryptionService.decryptServerData(encryptedUser);
        BigInteger userVerifier = new BigInteger(decryptedUser.getVerifier(), 16);

        // Compute SRP variables
        SrpUtils srpUtils = new SrpUtils();
        BigInteger serverPrivateValueB = srpUtils.generateRandomPrivateValue();
        BigInteger serverPublicValueB = srpUtils.computeB(userVerifier, serverPrivateValueB);

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
        SrpParamsResponseDTO srpParamsResponse = srpEncryptionService.encryptSrpParamsResponseDTO(serverPublicValueB,
                decryptedUser.getSalt());
        logger.info("SRP handshake completed for user: {}", srpParamsDTO.getDerivedUsername());
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
     * @throws Exception If an error occurs during decryption, session retrieval, user retrieval, or SRP verification.
     */
    @Override
    public UserLoginResponseDTO verifyClientProofAndAuthenticate(UserLoginRequestDTO encryptedUserLogin)
            throws Exception {
        // Decrypt the received data
        UserLoginDTO userLoginDTO = srpEncryptionService.decryptUserLoginRequestDTO(encryptedUserLogin);

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

        // Security check for null session attributes
        if (clientPublicValueA == null || serverPublicValueB == null || serverPrivateValueB == null
                || derivedUsername == null) {
            logger.warn("Authentication attempt with invalid session");
            throw new RuntimeException(AppConstants.AuthenticationErrors.INVALID_SESSION);
        }

        // Abort if A % N == 0
        if (clientPublicValueA.mod(AppConstants.N).equals(BigInteger.ZERO)) {
            logger.warn("Authentication attempt with invalid client value A for user: {}", derivedUsername);
            throw new RuntimeException(AppConstants.AuthenticationErrors.INVALID_CLIENT_VALUE_A);
        }

        // Retrieve the user information and decrypt the user data
        User encryptedUser = userRepository.findByUsername(derivedUsername);
        if (encryptedUser == null) {
            logger.warn("Authentication attempt for missing user: {}", derivedUsername);
            throw new RuntimeException(AppConstants.AuthenticationErrors.INVALID_SESSION);
        }
        User decryptedUser = userServerEncryptionService.decryptServerData(encryptedUser);
        BigInteger userVerifier = new BigInteger(decryptedUser.getVerifier(), 16);

        // Compute SRP variables
        SrpUtils srpUtils = new SrpUtils();
        BigInteger scramblingParameterU = srpUtils.computeU(serverPublicValueB);
        BigInteger sharedSecretS = srpUtils.computeS(clientPublicValueA, userVerifier, scramblingParameterU,
                serverPrivateValueB);
        String sessionKeyK = srpUtils.computeK(sharedSecretS);
        String serverProofM1 = srpUtils.computeM1(derivedUsername, decryptedUser.getSalt(), clientPublicValueA,
                serverPublicValueB, sessionKeyK);

        // Compare the client's M1 with the server's M1, if the values are equal then
        // both the client and server share the same secret
        if (!serverProofM1.equals(userLoginDTO.getEclientProofM1())) {
            logger.warn("Authentication failed - invalid proof for user: {}", derivedUsername);
            throw new RuntimeException(AppConstants.AuthenticationErrors.INVALID_PROOF);
        }

        // Compute server proof and generate session token
        String serverProofM2 = srpUtils.computeM2(clientPublicValueA, serverProofM1, sessionKeyK);
        String sessionToken = tokenService.generateToken(decryptedUser);

        // Clear session attributes after successful authentication
        httpSession.invalidate();

        // Create the response with the encrypted data
        UserLoginResponseDTO userLoginResponse = srpEncryptionService.encryptUserLoginResponseDTO(
                decryptedUser.getPublicKey(), decryptedUser.getPrivateKey(), sessionToken, serverProofM2,
                clientPublicKey);
        logger.info("User authenticated successfully: {}", derivedUsername);
        return userLoginResponse;
    }
}
