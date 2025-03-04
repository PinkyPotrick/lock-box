package com.lockbox.service;

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

    @Autowired
    private TokenService tokenService;

    @Autowired
    private UserService userService;

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    @Autowired
    private SrpEncryptionService srpEncryptionService;

    @Autowired
    private UserServerEncryptionService userServerEncryptionService;

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
    public UserRegistrationResponseDTO registerUser(UserRegistrationRequestDTO encryptedUserRegistration)
            throws Exception {
        // Create the registered user and generate a session token
        /*
         * User user2 = userService.createUser(encryptedUserRegistration); String sessionToken2 =
         * tokenService.generateToken(user2);
         * 
         * // Create the response with the encrypted session token of the client KeyGenerator keyGen =
         * KeyGenerator.getInstance(AppConstants.AES_CYPHER); keyGen.init(AppConstants.AES_256); SecretKey aesKey =
         * keyGen.generateKey(); EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
         * // UserProfileMapper userProfileMapper = new UserProfileMapper(); UserRegistrationResponseDTO
         * registerResponse = new UserRegistrationResponseDTO(); // UserProfileDTO userProfileDTO = new
         * UserProfileDTO(); EncryptedDataAesCbc encryptedSessionToken =
         * EncryptionUtils.encryptWithAESCBC(sessionToken2, aesKey);
         * registerResponse.setEncryptedSessionToken(encryptedDataAesCbcMapper.toDto(encryptedSessionToken));
         * registerResponse.setHelperAesKey(encryptedSessionToken.getAesKeyBase64()); return registerResponse;
         */

        // # ----------------------------------------------------------------------------- #

        // Decrypt the received data
        UserRegistrationDTO userRegistrationDTO = srpEncryptionService
                .decryptUserRegistrationRequestDTO(encryptedUserRegistration);

        // Create the registered user and generate a session token
        User user = userService.createUser(userRegistrationDTO);
        String sessionToken = tokenService.generateToken(user);

        // Create the response with the encrypted data
        UserRegistrationResponseDTO userRegistrationResponse = srpEncryptionService
                .encryptUserRegistrationResponseDTO(sessionToken);
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
     * @throws Exception
     */
    @Override
    public SrpParamsResponseDTO initiateSrpHandshake(SrpParamsRequestDTO encryprtedSrpParams) throws Exception {
        // Decrypt the received encrypted DTO data
        SrpParamsDTO srpParamsDTO = srpEncryptionService.decryptSrpParamsRequestDTO(encryprtedSrpParams);

        // Retrieve user information
        User encryptedUser = userRepository.findByUsername(srpParamsDTO.getDerivedUsername());
        if (encryptedUser == null) {
            throw new RuntimeException(AppConstants.AuthenticationErrors.INVALID_CREDENTIALS);
        }
        User decryptedUser = userServerEncryptionService.decryptServerData(encryptedUser);
        BigInteger userVerifier = new BigInteger(decryptedUser.getVerifier(), 16);

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
        SrpParamsResponseDTO srpParamsResponse = srpEncryptionService.encryptSrpParamsResponseDTO(serverPublicValueB,
                decryptedUser.getSalt());
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

        // Abort if A % N == 0
        if (clientPublicValueA.mod(AppConstants.N).equals(BigInteger.ZERO)) {
            throw new RuntimeException(AppConstants.AuthenticationErrors.INVALID_CLIENT_VALUE_A);
        }

        // Retrieve user information
        User encryptedUser = userRepository.findByUsername(derivedUsername);
        if (encryptedUser == null || clientPublicValueA == null || serverPublicValueB == null
                || serverPrivateValueB == null) {
            throw new RuntimeException(AppConstants.AuthenticationErrors.INVALID_SESSION);
        }
        User decryptedUser = userServerEncryptionService.decryptServerData(encryptedUser);
        BigInteger userVerifier = new BigInteger(decryptedUser.getVerifier(), 16);

        // Compute SRP variables
        BigInteger scramblingParameterU = SrpUtils.computeU(serverPublicValueB);
        BigInteger sharedSecretS = SrpUtils.computeS(clientPublicValueA, userVerifier, scramblingParameterU,
                serverPrivateValueB);
        String sessionKeyK = SrpUtils.computeK(sharedSecretS);
        String serverProofM1 = SrpUtils.computeM1(derivedUsername, decryptedUser.getSalt(), clientPublicValueA, serverPublicValueB,
                sessionKeyK);

        // Compare the client's M1 with the server's M1, if the values are equal then
        // both the client and server share the same secret
        if (!serverProofM1.equals(userLoginDTO.getEclientProofM1())) {
            throw new RuntimeException(AppConstants.AuthenticationErrors.INVALID_PROOF);
        }

        // Compute server proof and generate session token
        String serverProofM2 = SrpUtils.computeM2(clientPublicValueA, serverProofM1, sessionKeyK);
        String sessionToken = tokenService.generateToken(decryptedUser);

        // Clear session attributes after successful authentication
        httpSession.invalidate();

        // Create the response with the encrypted data
        UserLoginResponseDTO userLoginResponse = srpEncryptionService.encryptUserLoginResponseDTO(
                decryptedUser.getPublicKey(), decryptedUser.getPrivateKey(), sessionToken, serverProofM2,
                clientPublicKey);
        return userLoginResponse;
    }
}
