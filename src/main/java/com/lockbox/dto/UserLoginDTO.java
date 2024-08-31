package com.lockbox.dto;

public class UserLoginDTO {

    private String username;

    private String M1;

    private String clientPublicKey;

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

    public String getClientPublicKey() {
        return clientPublicKey;
    }

    public void setClientPublicKey(String clientPublicKey) {
        this.clientPublicKey = clientPublicKey;
    }
}
