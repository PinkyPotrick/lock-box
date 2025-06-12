package com.lockbox.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.totp.TotpSetupDTO;
import com.lockbox.dto.totp.TotpVerifyRequestDTO;
import com.lockbox.service.totp.TotpService;
import com.lockbox.utils.ResponseEntityBuilder;
import com.lockbox.utils.SecurityUtils;

@RestController
@RequestMapping("/api/users/2fa")
public class TotpController {

    @Autowired
    private TotpService totpService;

    @Autowired
    private SecurityUtils securityUtils;

    @PostMapping("/setup")
    public ResponseEntityDTO<TotpSetupDTO> setupTotp() {
        try {
            String userId = securityUtils.getCurrentUserId();
            TotpSetupDTO setupDTO = totpService.generateTotpSecret(userId);

            return new ResponseEntityBuilder<TotpSetupDTO>().setData(setupDTO).setMessage("TOTP setup initiated")
                    .build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to setup TOTP");
        }
    }

    @PostMapping("/verify")
    public ResponseEntityDTO<Boolean> verifyTotp(@RequestBody TotpVerifyRequestDTO requestDTO) {
        try {
            String userId = securityUtils.getCurrentUserId();
            boolean success = totpService.verifyTotpSetup(userId, requestDTO.getCode());

            return new ResponseEntityBuilder<Boolean>().setData(success)
                    .setMessage(success ? "TOTP verification successful" : "TOTP verification failed").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to verify TOTP");
        }
    }

    @PostMapping("/disable")
    public ResponseEntityDTO<Boolean> disableTotp() {
        try {
            String userId = securityUtils.getCurrentUserId();
            boolean success = totpService.disableTotp(userId);

            return new ResponseEntityBuilder<Boolean>().setData(success).setMessage("TOTP disabled successfully")
                    .build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to disable TOTP");
        }
    }
}