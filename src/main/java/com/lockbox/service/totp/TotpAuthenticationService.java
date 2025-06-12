package com.lockbox.service.totp;

import com.lockbox.dto.totp.TotpAuthenticationRequestDTO;

public interface TotpAuthenticationService {

    boolean verifyTotpOnly(TotpAuthenticationRequestDTO requestDTO) throws Exception;
}