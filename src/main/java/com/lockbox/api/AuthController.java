package com.lockbox.api;

import com.lockbox.dto.UserRegistrationDTO;
import com.lockbox.dto.mappers.EncryptedDataAesCbcMapper;
import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.UserLoginDTO;
import com.lockbox.dto.SrpParamsDTO;
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
import java.util.HashMap;
import java.util.Map;

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
            // Create the registered user
            User user = userService.createUser(userRegistration);

            // Generate and encrypt the session token with the client's public key
            String sessionToken = tokenService.generateToken(user);

            // Create the response with the encrypted session token of the client
            EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
            RegisterResponseDTO registerResponse = new RegisterResponseDTO();
            EncryptedDataAesCbc encryptedDataAesCbc = EncryptionUtils.encryptWithAESCBC(sessionToken);
            registerResponse.setEncryptedSessionToken(encryptedDataAesCbcMapper.toDto(encryptedDataAesCbc));
            registerResponse.setHelperAesKey(encryptedDataAesCbc.getAesKeyBase64());
            
            ResponseEntityBuilder<RegisterResponseDTO> responseEntityBuilder = new ResponseEntityBuilder<>();
            return responseEntityBuilder.setData(registerResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create()
                    .setMessage("Registering failed: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    // ------------------------------------------------ CLEAN CODE ABOVE -------------------------------------------------

    @PostMapping("/srp-params")
    public Map<String, Object> getSrpParams(@RequestBody SrpParamsDTO srpParams) {
        try {
            // Decrypt the received data
            String derivedKey = rsaKeyPairService.decryptWithServerPrivateKey(srpParams.getDerivedKey());
            String firstDecryptionUsername = rsaKeyPairService.decryptWithServerPrivateKey(srpParams.getUsername());
            String username = EncryptionUtils.decryptUsername(firstDecryptionUsername, derivedKey);
            
            EncryptedDataAesCbcDTO encryptedA = srpParams.getEncryptedA();
            if (encryptedA == null) {
                throw new RuntimeException("The public key cannot be empty");
            }
            BigInteger A = new BigInteger(EncryptionUtils.decryptWithAESCBC(encryptedA.getEncryptedDataBase64(), encryptedA.getIvBase64(), encryptedA.getHmacBase64(), srpParams.getHelperAesKey()), 16);;

            EncryptedDataAesCbcDTO encryptedPublicKey = srpParams.getEncryptedPublicKey();
            if (encryptedPublicKey == null) {
                throw new RuntimeException("The public key cannot be empty");
            }
            // TODO I think the client public key can be removed from here
            String clientPublicKey = EncryptionUtils.decryptWithAESCBC(encryptedPublicKey.getEncryptedDataBase64(), encryptedPublicKey.getIvBase64(), encryptedPublicKey.getHmacBase64(), srpParams.getHelperAesKey());

            // Retrieve user information
            User user = userRepository.findByUsername(firstDecryptionUsername);
            if (user == null) {
                throw new RuntimeException("Invalid credentials");
            }

            // Compute B and send it along with the salt
            BigInteger b = srpService.generatePrivateValue();
            BigInteger B = srpService.computeB(user.getVerifier(), b);
            String salt = rsaKeyPairService.decryptWithServerPrivateKey(user.getSalt());

            // Store values in session
            httpSession.setAttribute("A", A);
            httpSession.setAttribute("B", B);
            httpSession.setAttribute("b", b);
            httpSession.setAttribute("username", username); // TODO Should this value be stored decrypted ???

            Map<String, Object> response = new HashMap<>();
            EncryptedDataAesCbc encryptedDataAesCbc = EncryptionUtils.encryptWithAESCBC(B.toString(16));
            response.put("salt", salt);
            response.put("encryptedB", encryptedDataAesCbc);
            response.put("helperAesKey", encryptedDataAesCbc.getAesKeyBase64());

            return response;
        } catch (Exception e) {
            ExceptionBuilder.create()
                    .setMessage("Fetching SRP params failed: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @PostMapping("/srp-authenticate")
    public Map<String, String> authenticate(@RequestBody UserLoginDTO userLogin) {
        // Decrypt the received data
        String username = rsaKeyPairService.decryptWithServerPrivateKey(userLogin.getUsername());
        String M1 = rsaKeyPairService.decryptWithServerPrivateKey(userLogin.getM1());
        String clientPublicKey = rsaKeyPairService.decryptWithServerPrivateKey(userLogin.getClientPublicKey());

        // Retrieve session data and user information
        BigInteger A = (BigInteger) httpSession.getAttribute("A");
        BigInteger B = (BigInteger) httpSession.getAttribute("B");
        BigInteger b = (BigInteger) httpSession.getAttribute("b");
        // String username = (String) httpSession.getAttribute("username"); // this shouldn't be needed theoretically
        
        User user = userRepository.findByUsername(rsaKeyPairService.encryptWithPublicKey(username, clientPublicKey));
        if (user == null || A == null || B == null || b == null) {
            throw new RuntimeException("Session expired or invalid");
        }

        // Compute S, K, and M2
        BigInteger u = srpService.computeU(A, B);
        BigInteger v = new BigInteger(rsaKeyPairService.decryptWithServerPrivateKey(user.getVerifier()), 16);
        BigInteger S = srpService.computeS(A, v, u, B);
        byte[] K = srpService.computeK(S);

        // Verify M1
        String expectedM1 = srpService.computeM1(A, B, S, K);
        if (!expectedM1.equals(M1)) {
            throw new RuntimeException("Client verification failed");
        }

        // Generate M2
        String M2 = srpService.computeM2(A, M1, S, K);

        // Generate and encrypt the session token with the client's public key
        String sessionToken = tokenService.generateToken(user);
        String encryptedSessionToken = rsaKeyPairService.encryptWithPublicKey(sessionToken, clientPublicKey);

        // Clear session attributes after successful authentication
        httpSession.invalidate(); // TODO check if this is ultimately needed

        // Return M2 and the encrypted session token
        Map<String, String> response = new HashMap<>();
        response.put("encryptedM2", rsaKeyPairService.encryptWithPublicKey(M2, clientPublicKey));
        response.put("encryptedSessionToken", encryptedSessionToken);

        return response;
    }
}
