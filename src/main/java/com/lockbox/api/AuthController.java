package com.lockbox.api;

import com.lockbox.dto.UserRegistrationDTO;
import com.lockbox.dto.mappers.EncryptedDataAesCbcMapper;
import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.UserLoginDTO;
import com.lockbox.dto.UserLoginResponseDTO;
import com.lockbox.dto.SrpParamsDTO;
import com.lockbox.dto.SrpParamsResponseDTO;
import com.lockbox.dto.EncryptedDataAesCbcDTO;
import com.lockbox.dto.RegisterResponseDTO;
import com.lockbox.service.RSAKeyPairService;
import com.lockbox.service.SrpService;
import com.lockbox.service.TokenService;
import com.lockbox.service.UserService;
import com.lockbox.utils.ResponseEntityBuilder;
import com.lockbox.utils.EncryptionUtils;
import com.lockbox.utils.ExceptionBuilder;

import jakarta.servlet.http.HttpSession;
import jakarta.transaction.Transactional;

import com.lockbox.model.EncryptedDataAesCbc;
import com.lockbox.model.User;
import com.lockbox.repository.UserRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.security.PublicKey;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private SrpService srpService;

    @Autowired
    private HttpSession httpSession;

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    @Autowired
    private UserRepository userRepository;  // TODO delete later !!!

    @GetMapping("/public-key")
    public ResponseEntityDTO<String> getPublicKey() throws Exception {
        try {
            PublicKey publicKey = rsaKeyPairService.getPublicKey();
            
            ResponseEntityBuilder<String> responseEntityBuilder = new ResponseEntityBuilder<>();
            return responseEntityBuilder.setData(rsaKeyPairService.getPublicKeyInPEM(publicKey)).build();
        } catch (Exception e) {
            ExceptionBuilder.create()
                    .setMessage("Error retrieving public key: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @Transactional
    @PostMapping("/register")
    public ResponseEntityDTO<RegisterResponseDTO> registerUser(@RequestBody UserRegistrationDTO userRegistration) {
        try {
            // Create the registered user and generate a session token
            User user = userService.createUser(userRegistration);
            String sessionToken = tokenService.generateToken(user);

            // Create the response with the encrypted session token of the client
            EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
            RegisterResponseDTO registerResponse = new RegisterResponseDTO();
            EncryptedDataAesCbc encryptedSessionToken = EncryptionUtils.encryptWithAESCBC(sessionToken);
            registerResponse.setEncryptedSessionToken(encryptedDataAesCbcMapper.toDto(encryptedSessionToken));
            registerResponse.setHelperAesKey(encryptedSessionToken.getAesKeyBase64());
            
            ResponseEntityBuilder<RegisterResponseDTO> responseEntityBuilder = new ResponseEntityBuilder<>();
            return responseEntityBuilder.setData(registerResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create()
                    .setMessage("Registering failed: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @PostMapping("/srp-params")
    public ResponseEntityDTO<SrpParamsResponseDTO> getSrpParams(@RequestBody SrpParamsDTO srpParams) {
        try {
            // Decrypt the received data
            String derivedUsername = rsaKeyPairService.decryptWithServerPrivateKey(srpParams.getUsername());
            
            EncryptedDataAesCbcDTO encryptedClientPublicValueA = srpParams.getEncryptedClientPublicValueA();
            if (encryptedClientPublicValueA == null) {
                throw new RuntimeException("The public key cannot be empty");
            }
            BigInteger clientPublicValueA = new BigInteger(EncryptionUtils.decryptWithAESCBC(encryptedClientPublicValueA.getEncryptedDataBase64(), encryptedClientPublicValueA.getIvBase64(), encryptedClientPublicValueA.getHmacBase64(), srpParams.getHelperAesKey()), 16);

            EncryptedDataAesCbcDTO encryptedClientPublicKey = srpParams.getEncryptedClientPublicKey();
            if (encryptedClientPublicKey == null) {
                throw new RuntimeException("The public key cannot be empty");
            }
            String clientPublicKey = EncryptionUtils.decryptWithAESCBC(encryptedClientPublicKey.getEncryptedDataBase64(), encryptedClientPublicKey.getIvBase64(), encryptedClientPublicKey.getHmacBase64(), srpParams.getHelperAesKey());

            // Retrieve user information
            User user = userRepository.findByUsername(derivedUsername);
            if (user == null) {
                throw new RuntimeException("Invalid credentials");
            }
            BigInteger userVerifier = new BigInteger(user.getVerifier(), 16);

            // The salt needs to be decrypted first
            String salt = rsaKeyPairService.decryptWithServerPrivateKey(user.getSalt());

            // Compute SRP variables
            BigInteger serverPrivateValueB = srpService.generateRandomPrivateValue();
            BigInteger serverPublicValueB = srpService.computeB(userVerifier, serverPrivateValueB);

            // Store values in session
            httpSession.setAttribute("clientPublicValueA", clientPublicValueA);
            httpSession.setAttribute("serverPublicValueB", serverPublicValueB);
            httpSession.setAttribute("serverPrivateValueB", serverPrivateValueB);
            httpSession.setAttribute("derivedUsername", derivedUsername);
            httpSession.setAttribute("clientPublicKey", clientPublicKey);

            EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
            SrpParamsResponseDTO srpParamsResponse = new SrpParamsResponseDTO();
            EncryptedDataAesCbc encryptedServerPublicValueB = EncryptionUtils.encryptWithAESCBC(serverPublicValueB.toString(16));
            srpParamsResponse.setEncryptedServerPublicValueB(encryptedDataAesCbcMapper.toDto(encryptedServerPublicValueB)); //encryptedDataAesCbcMapper.toDto(encryptedSessionToken)
            srpParamsResponse.setHelperSrpParamsAesKey(encryptedServerPublicValueB.getAesKeyBase64());
            srpParamsResponse.setSalt(salt);

            ResponseEntityBuilder<SrpParamsResponseDTO> responseEntityBuilder = new ResponseEntityBuilder<>();
            return responseEntityBuilder.setData(srpParamsResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create()
                    .setMessage("Fetching SRP params failed: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @PostMapping("/srp-authenticate")
    public ResponseEntityDTO<UserLoginResponseDTO> authenticate(@RequestBody UserLoginDTO userLogin) {
        try {
            // Decrypt the received data
            String encryptedClientProofM1 = userLogin.getEncryptedClientProofM1();
            String clientProofM = rsaKeyPairService.decryptWithServerPrivateKey(encryptedClientProofM1);

            // Retrieve session data and user information
            BigInteger clientPublicValueA = (BigInteger) httpSession.getAttribute("clientPublicValueA");
            BigInteger serverPublicValueB = (BigInteger) httpSession.getAttribute("serverPublicValueB");
            BigInteger serverPrivateValueB = (BigInteger) httpSession.getAttribute("serverPrivateValueB");
            String derivedUsername = (String) httpSession.getAttribute("derivedUsername");
            String clientPublicKey = (String) httpSession.getAttribute("clientPublicKey");
            
            // Abort if A % N == 0
            if (clientPublicValueA.mod(srpService.getN()).equals(BigInteger.ZERO)) {
                throw new RuntimeException("Authentication failed: Invalid client value A.");
            }

            // Retrieve user information
            User user = userRepository.findByUsername(derivedUsername);
            if (user == null || clientPublicValueA == null || serverPublicValueB == null || serverPrivateValueB == null) {
                throw new RuntimeException("Session expired or invalid");
            }
            BigInteger userVerifier = new BigInteger(user.getVerifier(), 16);

            // The salt needs to be decrypted first
            String salt = rsaKeyPairService.decryptWithServerPrivateKey(user.getSalt());

            // Compute SRP variables
            BigInteger scramblingParameterU = srpService.computeU(serverPublicValueB);
            BigInteger sharedSecretS = srpService.computeS(clientPublicValueA, userVerifier, scramblingParameterU, serverPrivateValueB);
            String sessionKeyK = srpService.computeK(sharedSecretS);
            String serverProofM1 = srpService.computeM1(derivedUsername, salt, clientPublicValueA, serverPublicValueB, sessionKeyK);

            // Compare the client's M1 with the server's M1, if the values are equal then both the client and server share the same secret
            if (!serverProofM1.equals(clientProofM)) {
                throw new RuntimeException("Proof verification failed. Authorization aborted!");
            }

            String serverProofM2 = srpService.computeM2(clientPublicValueA, serverProofM1, sessionKeyK);
            String sessionToken = tokenService.generateToken(user);

            // Clear session attributes after successful authentication
            httpSession.invalidate();

            EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
            UserLoginResponseDTO userLoginResponse = new UserLoginResponseDTO();
            EncryptedDataAesCbc encryptedSessionToken = EncryptionUtils.encryptWithAESCBC(sessionToken);
            String encryptedServerProofM2 = rsaKeyPairService.encryptWithPublicKey(serverProofM2, clientPublicKey);
            userLoginResponse.setEncryptedSessionToken(encryptedDataAesCbcMapper.toDto(encryptedSessionToken));
            userLoginResponse.setHelperAuthenticateAesKey(encryptedSessionToken.getAesKeyBase64());
            userLoginResponse.setEncryptedServerProofM2(encryptedServerProofM2);

            ResponseEntityBuilder<UserLoginResponseDTO> responseEntityBuilder = new ResponseEntityBuilder<>();
            return responseEntityBuilder.setData(userLoginResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create()
                    .setMessage("Authentication failed: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }
}
