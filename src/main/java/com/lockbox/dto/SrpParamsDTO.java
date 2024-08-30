package com.lockbox.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class SrpParamsDTO {

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;

    @NotBlank(message = "A is required")
    @Pattern(regexp = "^[a-fA-F0-9]+$", message = "A must be a hex string")
    private String A;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getA() {
        return A;
    }

    public void setA(String a) {
        A = a;
    }
}
