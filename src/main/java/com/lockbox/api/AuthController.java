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
    private HttpSession httpSession;  // Injecting HttpSession for session management

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    @Autowired
    private UserRepository userRepository;  // TODO delete later

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
            String derivedKey = rsaKeyPairService.decryptWithServerPrivateKey(srpParams.getDerivedKey());
            String derivedUsername = rsaKeyPairService.decryptWithServerPrivateKey(srpParams.getUsername());
            String username = EncryptionUtils.decryptUsername(derivedUsername, derivedKey);
            
            EncryptedDataAesCbcDTO encryptedClientPublicValueA = srpParams.getEncryptedClientPublicValueA();
            if (encryptedClientPublicValueA == null) {
                throw new RuntimeException("The public key cannot be empty");
            }
            BigInteger clientPublicValueA = new BigInteger(EncryptionUtils.decryptWithAESCBC(encryptedClientPublicValueA.getEncryptedDataBase64(), encryptedClientPublicValueA.getIvBase64(), encryptedClientPublicValueA.getHmacBase64(), srpParams.getHelperAesKey()), 16);
            
            EncryptedDataAesCbcDTO encryptedClientPrivateValueA = srpParams.getEncryptedClientPrivateValueA();
            if (encryptedClientPrivateValueA == null) {
                throw new RuntimeException("The public key cannot be empty");
            }
            BigInteger clientPrivateValueA = new BigInteger(EncryptionUtils.decryptWithAESCBC(encryptedClientPrivateValueA.getEncryptedDataBase64(), encryptedClientPrivateValueA.getIvBase64(), encryptedClientPrivateValueA.getHmacBase64(), srpParams.getHelperAesKey()), 16);

            EncryptedDataAesCbcDTO encryptedClientPublicKey = srpParams.getEncryptedClientPublicKey();
            if (encryptedClientPublicKey == null) {
                throw new RuntimeException("The public key cannot be empty");
            }
            String clientPublicKey = EncryptionUtils.decryptWithAESCBC(encryptedClientPublicKey.getEncryptedDataBase64(), encryptedClientPublicKey.getIvBase64(), encryptedClientPublicKey.getHmacBase64(), srpParams.getHelperAesKey());

            System.out.println("[LOGIN] For debugging purposes:\n");
            System.out.println("username: " + username.toString());
            System.out.println("clientPublicValueA (A): " + clientPublicValueA.toString());
            System.out.println("clientPrivateValueA (a): " + clientPrivateValueA.toString());

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

            System.out.println("userVerifierBigInteger (v) (radix16): " + userVerifier.toString());
            System.out.println("userVerifierAsIsStoredInDB (v): " + user.getVerifier());
            System.out.println("salt (s): " + salt.toString());
            System.out.println("serverPublicValueB (B): " + serverPublicValueB.toString());
            System.out.println("serverPrivateValueB (b): " + serverPrivateValueB.toString());
            
            byte[] A_bytes = clientPublicValueA.toByteArray();
            byte[] B_bytes = serverPublicValueB.toByteArray();
            System.out.println("[in fetch srp req] A (bytes, hex): " + srpService.toHex(A_bytes));
            System.out.println("[in fetch srp req] B (bytes, hex): " + srpService.toHex(B_bytes));

            // Store values in session
            httpSession.setAttribute("clientPublicValueA", clientPublicValueA);
            httpSession.setAttribute("clientPrivateValueA", clientPrivateValueA);
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
            String encryptedClientProofM = userLogin.getEncryptedClientProofM();
            String clientProofM = rsaKeyPairService.decryptWithServerPrivateKey(encryptedClientProofM);

            // Retrieve session data and user information
            BigInteger clientPrivateValueA = (BigInteger) httpSession.getAttribute("clientPrivateValueA");
            BigInteger clientPublicValueA = (BigInteger) httpSession.getAttribute("clientPublicValueA");
            BigInteger serverPublicValueB = (BigInteger) httpSession.getAttribute("serverPublicValueB");
            BigInteger serverPrivateValueB = (BigInteger) httpSession.getAttribute("serverPrivateValueB");
            String derivedUsername = (String) httpSession.getAttribute("derivedUsername");
            String clientPublicKey = (String) httpSession.getAttribute("clientPublicKey");
            
            // Abort if A % N == 0
            System.out.println("Constant N: " + srpService.getN().toString());
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
            byte[] A_bytes = clientPublicValueA.toByteArray();
            byte[] B_bytes = serverPublicValueB.toByteArray();
            System.out.println("[before computeM1 func] A (bytes, hex): " + srpService.toHex(A_bytes));
            System.out.println("[before computeM1 func] B (bytes, hex): " + srpService.toHex(B_bytes));
            String serverProofM1 = srpService.computeM1(derivedUsername, salt, clientPublicValueA, serverPublicValueB, sessionKeyK);
            String serverProofM2 = srpService.computeM2(clientPublicValueA, clientProofM, sessionKeyK);

            System.out.println("serverPublicValueB (B): " + serverPublicValueB.toString());
            System.out.println("clientPublicValueA (A): " + clientPublicValueA.toString());
            System.out.println("clientPrivateValueA (A): " + clientPrivateValueA.toString());
            System.out.println("userVerifier (v) (radix16): " + userVerifier.toString());
            System.out.println("userVerifierAsIsStoredInDB (v): " + user.getVerifier());
            System.out.println("scramblingParameterU (u): " + scramblingParameterU.toString());
            System.out.println("serverPrivateValueB (b): " + serverPrivateValueB.toString());
            System.out.println("derivedUsername (U): " + derivedUsername.toString());
            System.out.println("salt (s): " + salt.toString());
            System.out.println("sharedSecretS (S): " + sharedSecretS.toString());
            System.out.println("sessionKeyK (K): " + sessionKeyK.toString());
            System.out.println("serverProofM1 (M1): " + serverProofM1.toString());
            System.out.println("serverProofM2 (M2): " + serverProofM2.toString());
            System.out.println("clientProofM (expectedM1): " + clientProofM.toString());

            System.out.println("We are going to try the frontend computation on the backend side to check if the computations are done in the same way as the frontend does them.");
            System.out.println("---------------------------START FRONTEND COMPUTATIONS ON BACKEND-------------------------");
            
            // BigInteger privateValueX_FE = srpService.computeX(salt, derivedUsername, "12345678");
            // BigInteger scramblingParameterU_FE = srpService.computeU(serverPublicValueB);
            // BigInteger sharedSecretS_FE = srpService.computeS_FE(serverPublicValueB, privateValueX_FE, clientPrivateValueA, scramblingParameterU_FE);
            // String sessionKeyK_FE = srpService.computeK(sharedSecretS_FE);
            // String clientProofM1_FE = srpService.computeM1(derivedUsername, salt, clientPublicValueA, serverPublicValueB, sessionKeyK_FE);
            // String clientProofM2_FE = srpService.computeM2(clientPublicValueA, clientProofM1_FE, sessionKeyK_FE);

            // System.out.println("privateValueX_FE (x_FE): " + privateValueX_FE.toString());
            // System.out.println("scramblingParameterU_FE (u_FE): " + scramblingParameterU_FE.toString());
            // System.out.println("sharedSecretS_FE (S_FE): " + sharedSecretS_FE.toString());
            // System.out.println("sessionKeyK_FE (K_FE): " + sessionKeyK_FE.toString());
            // System.out.println("clientProofM1_FE (M1_FE): " + clientProofM1_FE.toString());
            // System.out.println("clientProofM2_FE (M2_FE): " + clientProofM2_FE.toString());

            System.out.println("----------------------------END FRONTEND COMPUTATIONS ON BACKEND--------------------------");

            // Compare the client's M1 with the server's M1
            if (!serverProofM1.equals(clientProofM) || true) {
                throw new RuntimeException("Proof verification failed");
            }

            // String serverProofM2 = srpService.computeM2(clientPublicValueA, clientProofM, sessionKeyK);

            // // Compute S, K, and M2
            // BigInteger u = srpService.computeU(A, B);
            // // BigInteger v = new BigInteger(rsaKeyPairService.decryptWithServerPrivateKey(user.getVerifier()), 16);
            // BigInteger v = new BigInteger(user.getVerifier(), 16);
            // BigInteger S = srpService.computeS(A, v, u, B);
            // byte[] K = srpService.computeK(S);

            // Verify M1
            // String expectedM1 = srpService.computeM1(A, B, S, K);
            // if (!expectedM1.equals(M1)) {
            //     throw new RuntimeException("Client verification failed");
            // }

            // Generate M2
            // String M2 = srpService.computeM2(A, M1, S, K);

            // EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
            // EncryptedDataAesCbc encryptedSessionToken = EncryptionUtils.encryptWithAESCBC(sessionToken);

            // Return M2 and the encrypted session token
            // Map<String, Object> response = new HashMap<>();
            // response.put("encryptedM2", rsaKeyPairService.encryptWithPublicKey(M2, clientPublicKey));
            // response.put("encryptedM2", M2);
            // response.put("encryptedSessionToken", encryptedDataAesCbcMapper.toDto(encryptedSessionToken));
            // response.put("helperAesKey", encryptedSessionToken.getAesKeyBase64());

            // Generate a session token
            String sessionToken = tokenService.generateToken(user);

            // Clear session attributes after successful authentication
            httpSession.invalidate();

            EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
            UserLoginResponseDTO userLoginResponse = new UserLoginResponseDTO();
            EncryptedDataAesCbc encryptedSessionToken = EncryptionUtils.encryptWithAESCBC(sessionToken);
            String encryptedServerProofM = rsaKeyPairService.encryptWithPublicKey(encryptedClientProofM, clientPublicKey);
            userLoginResponse.setEncryptedSessionToken(encryptedDataAesCbcMapper.toDto(encryptedSessionToken));
            userLoginResponse.setHelperAuthenticateAesKey(encryptedSessionToken.getAesKeyBase64());
            userLoginResponse.setEncryptedServerProofM(encryptedServerProofM);

            ResponseEntityBuilder<UserLoginResponseDTO> responseEntityBuilder = new ResponseEntityBuilder<>();
            return responseEntityBuilder.setData(userLoginResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create()
                    .setMessage("Authentication failed: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    // ------------------------------------------------ CLEAN CODE ABOVE -------------------------------------------------

    // @PostMapping("/srp-params")
    // public Map<String, Object> getSrpParams2(@RequestBody SrpParamsDTO srpParams) {
    //     try {
    //         // Decrypt the received data
    //         String derivedKey = rsaKeyPairService.decryptWithServerPrivateKey(srpParams.getDerivedKey());
    //         String firstDecryptionUsername = rsaKeyPairService.decryptWithServerPrivateKey(srpParams.getUsername());
    //         String username = EncryptionUtils.decryptUsername(firstDecryptionUsername, derivedKey);
            
    //         EncryptedDataAesCbcDTO encryptedA = srpParams.getEncryptedClientPublicKey();
    //         if (encryptedA == null) {
    //             throw new RuntimeException("The public key cannot be empty");
    //         }
    //         BigInteger A = new BigInteger(EncryptionUtils.decryptWithAESCBC(encryptedA.getEncryptedDataBase64(), encryptedA.getIvBase64(), encryptedA.getHmacBase64(), srpParams.getHelperAesKey()), 16);

    //         // Retrieve user information
    //         User user = userRepository.findByUsername(firstDecryptionUsername);
    //         if (user == null) {
    //             throw new RuntimeException("Invalid credentials");
    //         }

    //         // Compute B and send it along with the salt
    //         BigInteger b = srpService.generateRandomPrivateValue();
    //         BigInteger B = srpService.computeB(user.getVerifier(), b);
    //         String salt = rsaKeyPairService.decryptWithServerPrivateKey(user.getSalt());

    //         // Store values in session
    //         httpSession.setAttribute("A", A);
    //         httpSession.setAttribute("B", B);
    //         httpSession.setAttribute("b", b);
    //         httpSession.setAttribute("username", firstDecryptionUsername); // TODO Should this value be stored decrypted ???

    //         System.out.println("user salt db decrypted = " + salt);
    //         System.out.println("user verif db = " + user.getVerifier());
    //         System.out.println("A = " + A.toString());
    //         System.out.println("B = " + B.toString());
    //         System.out.println("b = " + b.toString());
    //         System.out.println("username = " + username.toString());

    //         Map<String, Object> response = new HashMap<>();
    //         EncryptedDataAesCbc encryptedB = EncryptionUtils.encryptWithAESCBC(B.toString(16));
    //         response.put("salt", salt);
    //         response.put("encryptedB", encryptedB);
    //         response.put("helperAesKey", encryptedB.getAesKeyBase64());

    //         return response;
    //     } catch (Exception e) {
    //         ExceptionBuilder.create()
    //                 .setMessage("Fetching SRP params failed: " + e.getMessage())
    //                 .throwInternalServerErrorException();
    //         return null;
    //     }
    // }

    // @PostMapping("/srp-authenticate")
    // public Map<String, Object> authenticate(@RequestBody UserLoginDTO userLogin) {
    //     try {
    //         // Decrypt the received data
    //         // String derivedKey = rsaKeyPairService.decryptWithServerPrivateKey(userLogin.getDerivedKey());
    //         // String firstDecryptionUsername = rsaKeyPairService.decryptWithServerPrivateKey(userLogin.getUsername());
    //         // String username = EncryptionUtils.decryptUsername(firstDecryptionUsername, derivedKey);
    //         // String M1 = rsaKeyPairService.decryptWithServerPrivateKey(userLogin.getM1());
    //         String M1 = userLogin.getMmm();

    //         // Retrieve session data and user information
    //         BigInteger A = (BigInteger) httpSession.getAttribute("A");
    //         BigInteger B = (BigInteger) httpSession.getAttribute("B");
    //         BigInteger b = (BigInteger) httpSession.getAttribute("b");
    //         String username = (String) httpSession.getAttribute("username"); // this shouldn't be needed theoretically
            
    //         User user = userRepository.findByUsername(username);
    //         if (user == null || A == null || B == null || b == null) {
    //             throw new RuntimeException("Session expired or invalid");
    //         }

    //         // Compute S, K, and M2
    //         BigInteger u = srpService.computeU(A, B);
    //         // BigInteger v = new BigInteger(rsaKeyPairService.decryptWithServerPrivateKey(user.getVerifier()), 16);
    //         BigInteger v = new BigInteger(user.getVerifier(), 16);
    //         BigInteger S = srpService.computeS(A, v, u, B);
    //         byte[] K = srpService.computeK(S);

    //         // Verify M1
    //         String expectedM1 = srpService.computeM1(A, B, S, K);
    //         if (!expectedM1.equals(M1)) {
    //             throw new RuntimeException("Client verification failed");
    //         }

    //         // Generate M2
    //         String M2 = srpService.computeM2(A, M1, S, K);

    //         // Generate and encrypt the session token with the client's public key
    //         EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
    //         String sessionToken = tokenService.generateToken(user);
    //         EncryptedDataAesCbc encryptedSessionToken = EncryptionUtils.encryptWithAESCBC(sessionToken);

    //         // Clear session attributes after successful authentication
    //         httpSession.invalidate(); // TODO check if this is ultimately needed

    //         // Return M2 and the encrypted session token
    //         Map<String, Object> response = new HashMap<>();
    //         // response.put("encryptedM2", rsaKeyPairService.encryptWithPublicKey(M2, clientPublicKey));
    //         response.put("encryptedM2", M2);
    //         response.put("encryptedSessionToken", encryptedDataAesCbcMapper.toDto(encryptedSessionToken));
    //         // response.put("helperAesKey", encryptedSessionToken.getAesKeyBase64());

    //         return response;
    //     } catch (Exception e) {
    //         ExceptionBuilder.create()
    //                 .setMessage("Authentication failed: " + e.getMessage())
    //                 .throwInternalServerErrorException();
    //         return null;
    //     }
    // }
}
