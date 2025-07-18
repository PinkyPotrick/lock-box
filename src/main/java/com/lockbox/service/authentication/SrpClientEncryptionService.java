package com.lockbox.service.authentication;

import java.math.BigInteger;

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

public interface SrpClientEncryptionService {

    UserRegistrationDTO decryptUserRegistrationRequestDTO(UserRegistrationRequestDTO encryptedUserRegistration)
            throws Exception;

    UserRegistrationResponseDTO encryptUserRegistrationResponseDTO(String sessionToken) throws Exception;

    SrpParamsDTO decryptSrpParamsRequestDTO(SrpParamsRequestDTO encryprtedSrpParams) throws Exception;

    SrpParamsResponseDTO encryptSrpParamsResponseDTO(BigInteger serverPublicValueB, String salt, boolean requiresTotp, String temporaryTotpSessionId) throws Exception;

    UserLoginDTO decryptUserLoginRequestDTO(UserLoginRequestDTO encryptedUserLogin) throws Exception;

    UserLoginResponseDTO encryptUserLoginResponseDTO(String userPublicKey, String userPrivateKey, String sessionToken,
            String serverProofM2, String clientPublicKey) throws Exception;

    PasswordChangeInitDTO decryptPasswordChangeInitRequestDTO(PasswordChangeInitRequestDTO passwordChangeInitRequest)
            throws Exception;

    PasswordChangeInitResponseDTO encryptPasswordChangeInitResponseDTO(BigInteger serverPublicValueB, String salt)
            throws Exception;

    PasswordChangeCredentialsDTO decryptPasswordChangeCredentials(
            PasswordChangeCompleteRequestDTO passwordChangeCompleteRequest) throws Exception;

    PasswordChangeCompleteResponseDTO encryptPasswordChangeCompleteResponseDTO(String serverProofM2, boolean success,
            User user) throws Exception;
}