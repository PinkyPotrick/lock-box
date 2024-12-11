package com.lockbox.service;

import com.lockbox.dto.RegisterResponseDTO;
import com.lockbox.dto.SrpParamsRequestDTO;
import com.lockbox.dto.SrpParamsResponseDTO;
import com.lockbox.dto.UserLoginRequestDTO;
import com.lockbox.dto.UserLoginResponseDTO;
import com.lockbox.dto.UserRegistrationDTO;

public interface SrpService {

    RegisterResponseDTO registerUser(UserRegistrationDTO userRegistration) throws Exception;

    SrpParamsResponseDTO initiateSrpHandshake(SrpParamsRequestDTO srpParams) throws Exception;

    UserLoginResponseDTO verifyClientProofAndAuthenticate(UserLoginRequestDTO userLogin) throws Exception;
}
