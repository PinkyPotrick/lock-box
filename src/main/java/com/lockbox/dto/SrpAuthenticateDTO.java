package com.lockbox.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class SrpAuthenticateDTO {

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;

    @NotBlank(message = "M1 is required")
    @Pattern(regexp = "^[a-fA-F0-9]+$", message = "M1 must be a hex string")
    private String M1;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getM1() {
        return M1;
    }

    public void setM1(String m1) {
        M1 = m1;
    }
}
