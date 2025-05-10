package com.lockbox.service.authentication;

import com.lockbox.dto.authentication.login.UserLoginRequestDTO;
import com.lockbox.dto.authentication.login.UserLoginResponseDTO;
import com.lockbox.dto.authentication.registration.UserRegistrationRequestDTO;
import com.lockbox.dto.authentication.registration.UserRegistrationResponseDTO;
import com.lockbox.dto.authentication.srp.SrpParamsRequestDTO;
import com.lockbox.dto.authentication.srp.SrpParamsResponseDTO;

public interface SrpService {

    UserRegistrationResponseDTO registerUser(UserRegistrationRequestDTO userRegistration) throws Exception;

    SrpParamsResponseDTO initiateSrpHandshake(SrpParamsRequestDTO srpParams) throws Exception;

    UserLoginResponseDTO verifyClientProofAndAuthenticate(UserLoginRequestDTO userLogin) throws Exception;
}
