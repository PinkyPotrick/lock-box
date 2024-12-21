package com.lockbox.service;

import java.math.BigInteger;

import com.lockbox.dto.SrpParamsDTO;
import com.lockbox.dto.SrpParamsRequestDTO;
import com.lockbox.dto.SrpParamsResponseDTO;
import com.lockbox.dto.UserLoginDTO;
import com.lockbox.dto.UserLoginRequestDTO;
import com.lockbox.dto.UserLoginResponseDTO;
import com.lockbox.dto.UserRegistrationDTO;
import com.lockbox.dto.UserRegistrationRequestDTO;
import com.lockbox.dto.UserRegistrationResponseDTO;

public interface SrpEncryptionService {

    UserRegistrationDTO decryptUserRegistrationRequestDTO(UserRegistrationRequestDTO encryptedUserRegistration)
            throws Exception;

    UserRegistrationResponseDTO encryptUserRegistrationResponseDTO(String sessionToken) throws Exception;

    SrpParamsDTO decryptSrpParamsRequestDTO(SrpParamsRequestDTO encryprtedSrpParams) throws Exception;

    SrpParamsResponseDTO encryptSrpParamsResponseDTO(BigInteger serverPublicValueB, String salt) throws Exception;

    UserLoginDTO decryptUserLoginRequestDTO(UserLoginRequestDTO encryptedUserLogin) throws Exception;

    UserLoginResponseDTO encryptUserLoginResponseDTO(String userPublicKey, String userPrivateKey, String sessionToken,
            String serverProofM2, String clientPublicKey) throws Exception;

}