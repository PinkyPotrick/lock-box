package com.lockbox.service.authentication;

import com.lockbox.dto.authentication.login.UserLoginRequestDTO;
import com.lockbox.dto.authentication.login.UserLoginResponseDTO;
import com.lockbox.dto.authentication.password.PasswordChangeCompleteRequestDTO;
import com.lockbox.dto.authentication.password.PasswordChangeCompleteResponseDTO;
import com.lockbox.dto.authentication.password.PasswordChangeInitRequestDTO;
import com.lockbox.dto.authentication.password.PasswordChangeInitResponseDTO;
import com.lockbox.dto.authentication.registration.UserRegistrationRequestDTO;
import com.lockbox.dto.authentication.registration.UserRegistrationResponseDTO;
import com.lockbox.dto.authentication.srp.SrpParamsRequestDTO;
import com.lockbox.dto.authentication.srp.SrpParamsResponseDTO;

public interface SrpService {

    UserRegistrationResponseDTO registerUser(UserRegistrationRequestDTO userRegistration) throws Exception;

    SrpParamsResponseDTO initiateSrpHandshake(SrpParamsRequestDTO srpParams) throws Exception;

    UserLoginResponseDTO verifyClientProofAndAuthenticate(UserLoginRequestDTO userLogin) throws Exception;

    PasswordChangeInitResponseDTO initiatePasswordChange(PasswordChangeInitRequestDTO passwordChangeInit)
            throws Exception;

    PasswordChangeCompleteResponseDTO completePasswordChange(PasswordChangeCompleteRequestDTO completeRequest)
            throws Exception;
}
