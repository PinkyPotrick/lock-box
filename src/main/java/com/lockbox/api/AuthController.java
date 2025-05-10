package com.lockbox.api;

import java.security.PublicKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.authentication.login.UserLoginRequestDTO;
import com.lockbox.dto.authentication.login.UserLoginResponseDTO;
import com.lockbox.dto.authentication.registration.UserRegistrationRequestDTO;
import com.lockbox.dto.authentication.registration.UserRegistrationResponseDTO;
import com.lockbox.dto.authentication.srp.SrpParamsRequestDTO;
import com.lockbox.dto.authentication.srp.SrpParamsResponseDTO;
import com.lockbox.service.authentication.AuthenticationService;
import com.lockbox.service.authentication.SrpService;
import com.lockbox.service.encryption.RSAKeyPairService;
import com.lockbox.utils.ExceptionBuilder;
import com.lockbox.utils.ResponseEntityBuilder;

import jakarta.transaction.Transactional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    @Autowired
    private SrpService srpService;

    @Autowired
    private AuthenticationService authenticationService;

    @GetMapping("/public-key")
    public ResponseEntityDTO<String> getPublicKey() throws Exception {
        try {
            PublicKey publicKey = rsaKeyPairService.getPublicKey();
            ResponseEntityBuilder<String> responseEntityBuilder = new ResponseEntityBuilder<>();
            return responseEntityBuilder.setData(rsaKeyPairService.getPublicKeyInPEM(publicKey)).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Error retrieving public key").throwInternalServerErrorException();
            return null;
        }
    }

    @Transactional
    @PostMapping("/register")
    public ResponseEntityDTO<UserRegistrationResponseDTO> registerUser(
            @RequestBody UserRegistrationRequestDTO userRegistration) {
        try {
            UserRegistrationResponseDTO registerResponse = srpService.registerUser(userRegistration);
            ResponseEntityBuilder<UserRegistrationResponseDTO> responseEntityBuilder = new ResponseEntityBuilder<>();
            return responseEntityBuilder.setData(registerResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Registration failed").throwInternalServerErrorException();
            return null;
        }
    }

    @PostMapping("/srp-params")
    public ResponseEntityDTO<SrpParamsResponseDTO> getSrpParams(@RequestBody SrpParamsRequestDTO srpParams) {
        try {
            SrpParamsResponseDTO srpParamsResponse = srpService.initiateSrpHandshake(srpParams);
            ResponseEntityBuilder<SrpParamsResponseDTO> responseEntityBuilder = new ResponseEntityBuilder<>();
            return responseEntityBuilder.setData(srpParamsResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Authentication failed").throwInternalServerErrorException();
            return null;
        }
    }

    // TEST USERS: pfilip 1234
    // usermare 12345678

    @PostMapping("/srp-authenticate")
    public ResponseEntityDTO<UserLoginResponseDTO> authenticateUser(@RequestBody UserLoginRequestDTO userLogin) {
        try {
            UserLoginResponseDTO userLoginResponse = srpService.verifyClientProofAndAuthenticate(userLogin);
            ResponseEntityBuilder<UserLoginResponseDTO> responseEntityBuilder = new ResponseEntityBuilder<>();
            return responseEntityBuilder.setData(userLoginResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Authentication failed").throwInternalServerErrorException();
            return null;
        }
    }

    @PostMapping("/logout")
    public ResponseEntityDTO<String> logout() {
        try {
            authenticationService.logout();
            ResponseEntityBuilder<String> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData("Logged out successfully").build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Logout failed").throwInternalServerErrorException();
            return null;
        }
    }
}
