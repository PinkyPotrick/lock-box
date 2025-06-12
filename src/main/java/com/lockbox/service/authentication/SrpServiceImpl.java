package com.lockbox.service.authentication;

import java.math.BigInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import com.lockbox.model.User;
import com.lockbox.model.enums.ActionType;
import com.lockbox.model.enums.LogLevel;
import com.lockbox.model.enums.OperationType;
import com.lockbox.repository.UserRepository;
import com.lockbox.service.SessionKeyStoreService;
import com.lockbox.service.auditlog.AuditLogService;
import com.lockbox.service.notification.NotificationCreationService;
import com.lockbox.service.token.TokenService;
import com.lockbox.service.totp.TemporarySessionService;
import com.lockbox.service.user.UserServerEncryptionServiceImpl;
import com.lockbox.service.user.UserService;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.AppConstants.ActionStatus;
import com.lockbox.utils.AppConstants.LogMessages;
import com.lockbox.utils.EncryptionUtils;
import com.lockbox.utils.SrpUtils;

import jakarta.servlet.http.HttpSession;

@Service
public class SrpServiceImpl implements SrpService {

    private static final Logger logger = LoggerFactory.getLogger(SrpServiceImpl.class);

    @Autowired
    private TokenService tokenService;

    @Autowired
    private UserService userService;

    @Autowired
    private SrpClientEncryptionService srpEncryptionService;

    @Autowired
    private UserServerEncryptionServiceImpl userServerEncryptionService;

    @Autowired
    private TemporarySessionService temporarySessionService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private HttpSession httpSession;

    @Autowired
    private SessionKeyStoreService sessionKeyStore;

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private NotificationCreationService notificationCreationService;

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
        String decryptedUsername = EncryptionUtils.decryptUsername(userRegistrationDTO.getDerivedUsername(),
                userRegistrationDTO.getDerivedKey());
        String sessionToken = tokenService.generateToken(user, decryptedUsername);

        // Store the keys in session after successful registration
        sessionKeyStore.storeUserKeys(user.getPublicKey(), user.getPrivateKey(), user.getAesKey());

        // Record successful authentication
        authenticationService.recordSuccessfulAuthentication(user.getId());

        // Create the response with the encrypted data
        UserRegistrationResponseDTO userRegistrationResponse = srpEncryptionService
                .encryptUserRegistrationResponseDTO(sessionToken);

        logger.info("User registered successfully: {}", userRegistrationDTO.getDerivedUsername());
        try {
            auditLogService.logUserAction(user.getId(), ActionType.USER_REGISTRATION, OperationType.WRITE,
                    LogLevel.INFO, user.getId(), "User Registration", ActionStatus.SUCCESS, null,
                    "New user registered successfully");
        } catch (Exception e) {
            logger.error("Failed to create audit log for user registration: {}", e.getMessage());
        }

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
        httpSession.setAttribute(AppConstants.HttpSessionAttributes.DERIVED_KEY, srpParamsDTO.getDerivedKey());
        httpSession.setAttribute(AppConstants.HttpSessionAttributes.CLIENT_PUBLIC_KEY,
                srpParamsDTO.getClientPublicKey());

        // Check if TOTP is enabled and store in session
        boolean totpEnabled = decryptedUser.isTotpEnabled();
        httpSession.setAttribute(AppConstants.HttpSessionAttributes.REQUIRES_TOTP, totpEnabled);
        httpSession.setAttribute(AppConstants.HttpSessionAttributes.TOTP_VERIFIED, false);

        // If TOTP is enabled, create a temporary session ID for TOTP verification
        String temporarySessionId = null;
        if (totpEnabled) {
            temporarySessionId = temporarySessionService.createTemporarySession(decryptedUser.getId());
        }

        // Create the response with the encrypted data
        SrpParamsResponseDTO srpParamsResponse = srpEncryptionService.encryptSrpParamsResponseDTO(serverPublicValueB,
                decryptedUser.getSalt(), totpEnabled, temporarySessionId);
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
        String derivedKey = (String) httpSession.getAttribute(AppConstants.HttpSessionAttributes.DERIVED_KEY);
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
            logger.warn("Authentication failed - invalid proof for user: {}", decryptedUser.getId());
            authenticationService.recordFailedAuthentication(decryptedUser.getId(),
                    AppConstants.AuthenticationErrors.INVALID_PROOF);
            try {
                auditLogService.logUserAction(decryptedUser.getId(), ActionType.LOGIN_FAILED, OperationType.READ,
                        LogLevel.WARNING, null, "Authentication System", ActionStatus.FAILURE, "Invalid proof",
                        "Failed login attempt - invalid authentication proof");
            } catch (Exception ex) {
                logger.error(LogMessages.AUDIT_LOG_FAILED, ex.getMessage());
            }
            throw new RuntimeException(AppConstants.AuthenticationErrors.INVALID_PROOF);
        }

        // Check if TOTP was required and verified
        Boolean requiresTotp = (Boolean) httpSession.getAttribute(AppConstants.HttpSessionAttributes.REQUIRES_TOTP);
        Boolean totpVerified = (Boolean) httpSession.getAttribute(AppConstants.HttpSessionAttributes.TOTP_VERIFIED);

        if (Boolean.TRUE.equals(requiresTotp) && !Boolean.TRUE.equals(totpVerified)) {
            logger.warn("TOTP verification required but not completed for user: {}", decryptedUser.getId());
            throw new Exception(AppConstants.AuthenticationErrors.TOTP_NOT_VERIFIED);
        }

        // Compute server proof and generate session token
        String serverProofM2 = srpUtils.computeM2(clientPublicValueA, serverProofM1, sessionKeyK);
        String decryptedUsername = EncryptionUtils.decryptUsername(derivedUsername, derivedKey);
        String sessionToken = tokenService.generateToken(decryptedUser, decryptedUsername);

        // Clear session attributes after successful authentication
        httpSession.invalidate();

        // Store the keys in session after successful authentication
        sessionKeyStore.storeUserKeys(encryptedUser.getPublicKey(), encryptedUser.getPrivateKey(),
                encryptedUser.getAesKey());

        // Record successful authentication
        authenticationService.recordSuccessfulAuthentication(decryptedUser.getId());

        // Create the response with the encrypted data
        UserLoginResponseDTO userLoginResponse = srpEncryptionService.encryptUserLoginResponseDTO(
                decryptedUser.getPublicKey(), decryptedUser.getPrivateKey(), sessionToken, serverProofM2,
                clientPublicKey);
        logger.info("User authenticated successfully: {}", decryptedUser.getId());
        return userLoginResponse;
    }

    /**
     * Initiates a password change process using the SRP (Secure Remote Password) protocol by generating server-side
     * values.
     *
     * This method represents the first step in the password change process and follows the same SRP protocol pattern
     * used during login. It decrypts the received password change request data, retrieves and decrypts the user's
     * current verifier, and generates a new server-side ephemeral value B. These values are stored in the session with
     * a distinct namespace to separate them from regular authentication data, and the server's public value B along
     * with the user's salt are returned to the client.
     *
     * The client will use these values, along with knowledge of the current password, to generate a proof that it knows
     * the current password. This approach ensures that only users who know their current password can change it.
     *
     * @param passwordChangeInit - The encrypted password change initialization data received from the client, including
     *                           the client's public ephemeral value A and derived username.
     * @return A {@link PasswordChangeInitResponseDTO} containing the server's public ephemeral value B and the user's
     *         salt for the current password, encrypted for secure transmission.
     * @throws Exception If an error occurs during decryption, user retrieval, or SRP computation.
     */
    @Override
    public PasswordChangeInitResponseDTO initiatePasswordChange(PasswordChangeInitRequestDTO passwordChangeInit)
            throws Exception {
        // Decrypt the received encrypted DTO data
        PasswordChangeInitDTO initDTO = srpEncryptionService.decryptPasswordChangeInitRequestDTO(passwordChangeInit);
        logger.info("Password change initiated for user: {}", initDTO.getDerivedUsername());

        // Retrieve the user information and decrypt the user data
        User encryptedUser = userRepository.findByUsername(initDTO.getDerivedUsername());
        if (encryptedUser == null) {
            logger.warn("Password change attempt for non-existent user: {}", initDTO.getDerivedUsername());
            throw new RuntimeException(AppConstants.AuthenticationErrors.INVALID_CREDENTIALS);
        }
        User decryptedUser = userServerEncryptionService.decryptServerData(encryptedUser);
        BigInteger userVerifier = new BigInteger(decryptedUser.getVerifier(), 16);

        // Compute SRP variables
        SrpUtils srpUtils = new SrpUtils();
        BigInteger serverPrivateValueB = srpUtils.generateRandomPrivateValue();
        BigInteger serverPublicValueB = srpUtils.computeB(userVerifier, serverPrivateValueB);

        // Store temporary user values in session with distinct namespace for password change
        httpSession.setAttribute(AppConstants.HttpSessionAttributes.PASSWORD_CLIENT_PUBLIC_VALUE_A,
                initDTO.getClientPublicValueA());
        httpSession.setAttribute(AppConstants.HttpSessionAttributes.PASSWORD_SERVER_PUBLIC_VALUE_B, serverPublicValueB);
        httpSession.setAttribute(AppConstants.HttpSessionAttributes.PASSWORD_SERVER_PRIVATE_VALUE_B,
                serverPrivateValueB);
        httpSession.setAttribute(AppConstants.HttpSessionAttributes.PASSWORD_DERIVED_USERNAME,
                initDTO.getDerivedUsername());
        httpSession.setAttribute(AppConstants.HttpSessionAttributes.PASSWORD_USER_ID, decryptedUser.getId());

        // Create the response with the encrypted data
        PasswordChangeInitResponseDTO response = srpEncryptionService
                .encryptPasswordChangeInitResponseDTO(serverPublicValueB, decryptedUser.getSalt());
        logger.info("Password change handshake completed for user: {}", initDTO.getDerivedUsername());
        return response;
    }

    /**
     * Completes the password change process by verifying the user's knowledge of their current password and updating
     * their credentials.
     *
     * This method handles the second phase of the password change SRP protocol. It retrieves the stored session values
     * from the password change initiation step and verifies that the client has provided a valid proof of knowledge
     * (M1) of the current password. This proof is calculated using the same SRP authentication mechanism used during
     * login.
     *
     * If the client's proof matches the server's calculated proof, the method updates the user's credentials with the
     * new verifier, salt, and derived username provided in the request. These values represent the user's new password.
     * The method then generates a server proof (M2) as confirmation of the successful change and returns it to the
     * client.
     *
     * This two-step process ensures that: 1. Only users who know their current password can change it 2. The new
     * password is never transmitted in plaintext 3. The server can verify the legitimacy of the request without knowing
     * either the old or new passwords
     *
     * @param completeRequest - The password change completion request, containing proof of knowledge of the current
     *                        password and the new verifier and salt for the new password.
     * @return A {@link PasswordChangeCompleteResponseDTO} containing the server's proof (M2) and success status,
     *         encrypted for secure transmission back to the client.
     * @throws Exception If an error occurs during verification, user update, or if the client's proof is invalid.
     */
    @Override
    public PasswordChangeCompleteResponseDTO completePasswordChange(PasswordChangeCompleteRequestDTO completeRequest)
            throws Exception {
        // Retrieve session data for password change
        BigInteger clientPublicValueA = (BigInteger) httpSession
                .getAttribute(AppConstants.HttpSessionAttributes.PASSWORD_CLIENT_PUBLIC_VALUE_A);
        BigInteger serverPublicValueB = (BigInteger) httpSession
                .getAttribute(AppConstants.HttpSessionAttributes.PASSWORD_SERVER_PUBLIC_VALUE_B);
        BigInteger serverPrivateValueB = (BigInteger) httpSession
                .getAttribute(AppConstants.HttpSessionAttributes.PASSWORD_SERVER_PRIVATE_VALUE_B);
        String derivedUsername = (String) httpSession
                .getAttribute(AppConstants.HttpSessionAttributes.PASSWORD_DERIVED_USERNAME);
        String userId = (String) httpSession.getAttribute(AppConstants.HttpSessionAttributes.PASSWORD_USER_ID);

        // Security check for null session attributes
        if (clientPublicValueA == null || serverPublicValueB == null || serverPrivateValueB == null
                || derivedUsername == null || userId == null) {
            logger.warn("Password change attempt with invalid session");
            throw new RuntimeException(AppConstants.AuthenticationErrors.INVALID_SESSION);
        }

        // Retrieve the user information
        User encryptedUser = userRepository.findByUsername(derivedUsername);
        if (encryptedUser == null) {
            logger.warn("Password change attempt for missing user: {}", derivedUsername);
            throw new RuntimeException(AppConstants.AuthenticationErrors.INVALID_SESSION);
        }
        User decryptedUser = userServerEncryptionService.decryptServerData(encryptedUser);
        BigInteger userVerifier = new BigInteger(decryptedUser.getVerifier(), 16);

        // Decrypt the client's data including proof and new credentials
        PasswordChangeCredentialsDTO credentials = srpEncryptionService
                .decryptPasswordChangeCredentials(completeRequest);

        // Compute SRP variables for verifying current password
        SrpUtils srpUtils = new SrpUtils();
        BigInteger scramblingParameterU = srpUtils.computeU(serverPublicValueB);
        BigInteger sharedSecretS = srpUtils.computeS(clientPublicValueA, userVerifier, scramblingParameterU,
                serverPrivateValueB);
        String sessionKeyK = srpUtils.computeK(sharedSecretS);
        String serverProofM1 = srpUtils.computeM1(derivedUsername, decryptedUser.getSalt(), clientPublicValueA,
                serverPublicValueB, sessionKeyK);

        // Compare the client's M1 with the server's M1
        if (!serverProofM1.equals(credentials.getClientProofM1())) {
            logger.warn("Password change failed - invalid proof for user: {}", userId);
            authenticationService.recordFailedAuthentication(userId, AppConstants.AuthenticationErrors.INVALID_PROOF);
            throw new RuntimeException(AppConstants.AuthenticationErrors.INVALID_PROOF);
        }

        // Compute server proof for response
        String serverProofM2 = srpUtils.computeM2(clientPublicValueA, serverProofM1, sessionKeyK);

        // Update the user with new credentials
        decryptedUser.setUsername(credentials.getNewDerivedUsername());
        decryptedUser.setSalt(credentials.getNewSalt());
        decryptedUser.setVerifier(credentials.getNewVerifier());

        // Re-encrypt and save
        User updatedEncryptedUser = userServerEncryptionService.encryptServerData(decryptedUser);
        userRepository.save(updatedEncryptedUser);

        // Clear session attributes after successful authentication
        httpSession.invalidate();

        logger.info("Password successfully changed for user ID: {}", userId);

        try {
            auditLogService.logUserAction(userId, ActionType.PASSWORD_CHANGE, OperationType.UPDATE, LogLevel.INFO,
                    userId, "User Account", ActionStatus.SUCCESS, null, "Password changed successfully");
        } catch (Exception e) {
            logger.error("Failed to create audit log for password change: {}", e.getMessage());
        }

        // After saving the updated user
        try {
            notificationCreationService.createPasswordChangedNotification(userId);
        } catch (Exception ex) {
            // Don't block password change if notification fails
            logger.error("Failed to create password change notification: {}", ex.getMessage());
        }

        // Create and return the encrypted response
        return srpEncryptionService.encryptPasswordChangeCompleteResponseDTO(serverProofM2, true, decryptedUser);
    }
}
