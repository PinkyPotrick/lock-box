package com.lockbox.api;

import com.lockbox.dto.UserRegistrationRequestDTO;
import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.UserLoginRequestDTO;
import com.lockbox.dto.UserLoginResponseDTO;
import com.lockbox.dto.SrpParamsRequestDTO;
import com.lockbox.dto.SrpParamsResponseDTO;
import com.lockbox.dto.UserRegistrationResponseDTO;
import com.lockbox.service.RSAKeyPairService;
import com.lockbox.service.SrpService;
import com.lockbox.utils.ResponseEntityBuilder;
import com.lockbox.utils.ExceptionBuilder;

import jakarta.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.security.PublicKey;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    @Autowired
    private SrpService srpService;

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
}
