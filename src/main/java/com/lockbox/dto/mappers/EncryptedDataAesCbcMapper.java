package com.lockbox.dto.mappers;

import com.lockbox.dto.EncryptedDataAesCbcDTO;
import com.lockbox.model.EncryptedDataAesCbc;

public class EncryptedDataAesCbcMapper {

    // Methods for the EncryptedDataAesCbc class
    public EncryptedDataAesCbcDTO toDto(final EncryptedDataAesCbc ecryptedDataAESCBC) {
        if (ecryptedDataAESCBC == null) {
            return null;
        }

        EncryptedDataAesCbcDTO encryptedDataAesCbcDTO = new EncryptedDataAesCbcDTO();
        encryptedDataAesCbcDTO.setEncryptedDataBase64(ecryptedDataAESCBC.getEncryptedDataBase64());
        encryptedDataAesCbcDTO.setIvBase64(ecryptedDataAESCBC.getIvBase64());
        encryptedDataAesCbcDTO.setHmacBase64(ecryptedDataAESCBC.getHmacBase64());

        return encryptedDataAesCbcDTO;
    }

    public EncryptedDataAesCbc fromDto(final EncryptedDataAesCbcDTO encryptedDataAesCbcDTO) {
        if (encryptedDataAesCbcDTO == null) {
            return null;
        }

        EncryptedDataAesCbc encryptedDataAesCbc = new EncryptedDataAesCbc();
        encryptedDataAesCbc.setEncryptedDataBase64(encryptedDataAesCbcDTO.getEncryptedDataBase64());
        encryptedDataAesCbc.setIvBase64(encryptedDataAesCbcDTO.getIvBase64());
        encryptedDataAesCbc.setHmacBase64(encryptedDataAesCbcDTO.getHmacBase64());

        return encryptedDataAesCbc;
    }

    // // Methods for the RegisterResponseDTO class
    // public RegisterResponseDTO toRegisterResponseDto(final EncryptedDataAesCbc ecryptedDataAESCBC) {
    //     if (ecryptedDataAESCBC == null) {
    //         return null;
    //     }

    //     RegisterResponseDTO registerResponseDTO = new RegisterResponseDTO();
    //     registerResponseDTO.setEncryptedSessionToken(toEncryptedSessionTokenDto(ecryptedDataAESCBC));
    //     registerResponseDTO.setHelperAesKey(ecryptedDataAESCBC.getAesKeyBase64());

    //     return registerResponseDTO;
    // }

    // public EncryptedDataAesCbc fromRegisterResponseDto(final RegisterResponseDTO registerResponseDTO) {
    //     if (registerResponseDTO == null) {
    //         return null;
    //     }

    //     EncryptedDataAesCbc encryptedDataAESCBC = fromEncryptedSessionTokenDto(registerResponseDTO.getEncryptedSessionToken());
    //     encryptedDataAESCBC.setAesKeyBase64(registerResponseDTO.getHelperAesKey());

    //     return encryptedDataAESCBC;
    // }

    // // Methods for the EncryptedVerifierDTO class
    // public EncryptedVerifierDTO toEncryptedVerifierDto(final EncryptedDataAesCbc encryptedVerifier) {
    //     if (encryptedVerifier == null) {
    //         return null;
    //     }

    //     EncryptedVerifierDTO encryptedVerifierDTO = new EncryptedVerifierDTO();
    //     encryptedVerifierDTO.setVerifier(encryptedVerifier.getEncryptedDataBase64());
    //     encryptedVerifierDTO.setIvVerifier(encryptedVerifier.getIvBase64());
    //     encryptedVerifierDTO.setHmacVerifier(encryptedVerifier.getHmacBase64());

    //     return encryptedVerifierDTO;
    // }

    // public EncryptedDataAesCbc fromEncryptedVerifierDto(final EncryptedVerifierDTO encryptedVerifierDTO) {
    //     if (encryptedVerifierDTO == null) {
    //         return null;
    //     }

    //     EncryptedDataAesCbc encryptedDataAESCBC = new EncryptedDataAesCbc();
    //     encryptedDataAESCBC.setEncryptedDataBase64(encryptedVerifierDTO.getVerifier());
    //     encryptedDataAESCBC.setIvBase64(encryptedVerifierDTO.getIvVerifier());
    //     encryptedDataAESCBC.setHmacBase64(encryptedVerifierDTO.getHmacVerifier());

    //     return encryptedDataAESCBC;
    // }

    // // Methods for the EncryptedPublicKeyDTO class
    // public EncryptedPublicKeyDTO toEncryptedPublicKeyDto(final EncryptedDataAesCbc encryptedPublicKey) {
    //     if (encryptedPublicKey == null) {
    //         return null;
    //     }

    //     EncryptedPublicKeyDTO encryptedPublicKeyDTO = new EncryptedPublicKeyDTO();
    //     encryptedPublicKeyDTO.setClientPublicKey(encryptedPublicKey.getEncryptedDataBase64());
    //     encryptedPublicKeyDTO.setIvClientPublicKey(encryptedPublicKey.getIvBase64());
    //     encryptedPublicKeyDTO.setHmacClientPublicKey(encryptedPublicKey.getHmacBase64());

    //     return encryptedPublicKeyDTO;
    // }

    // public EncryptedDataAesCbc fromEncryptedPublicKeyDto(final EncryptedPublicKeyDTO encryptedPublicKeyDTO) {
    //     if (encryptedPublicKeyDTO == null) {
    //         return null;
    //     }

    //     EncryptedDataAesCbc encryptedDataAESCBC = new EncryptedDataAesCbc();
    //     encryptedDataAESCBC.setEncryptedDataBase64(encryptedPublicKeyDTO.getClientPublicKey());
    //     encryptedDataAESCBC.setIvBase64(encryptedPublicKeyDTO.getIvClientPublicKey());
    //     encryptedDataAESCBC.setHmacBase64(encryptedPublicKeyDTO.getHmacClientPublicKey());

    //     return encryptedDataAESCBC;
    // }

    // // Methods for the EncryptedPrivateKeyDTO class
    // public EncryptedPrivateKeyDTO toEncryptedPrivateKeyDto(final EncryptedDataAesCbc encryptedPrivateKey) {
    //     if (encryptedPrivateKey == null) {
    //         return null;
    //     }

    //     EncryptedPrivateKeyDTO encryptedPrivateKeyDTO = new EncryptedPrivateKeyDTO();
    //     encryptedPrivateKeyDTO.setClientPrivateKey(encryptedPrivateKey.getEncryptedDataBase64());
    //     encryptedPrivateKeyDTO.setIvClientPrivateKey(encryptedPrivateKey.getIvBase64());
    //     encryptedPrivateKeyDTO.setHmacClientPrivateKey(encryptedPrivateKey.getHmacBase64());

    //     return encryptedPrivateKeyDTO;
    // }

    // public EncryptedDataAesCbc fromEncryptedPrivateKeyDto(final EncryptedPrivateKeyDTO encryptedPrivateKeyDTO) {
    //     if (encryptedPrivateKeyDTO == null) {
    //         return null;
    //     }

    //     EncryptedDataAesCbc encryptedDataAESCBC = new EncryptedDataAesCbc();
    //     encryptedDataAESCBC.setEncryptedDataBase64(encryptedPrivateKeyDTO.getClientPrivateKey());
    //     encryptedDataAESCBC.setIvBase64(encryptedPrivateKeyDTO.getIvClientPrivateKey());
    //     encryptedDataAESCBC.setHmacBase64(encryptedPrivateKeyDTO.getHmacClientPrivateKey());

    //     return encryptedDataAESCBC;
    // }

    // // Methods for the EncryptedSessionTokenDTO class
    // public EncryptedSessionTokenDTO toEncryptedSessionTokenDto(final EncryptedDataAesCbc encryptedSessionToken) {
    //     if (encryptedSessionToken == null) {
    //         return null;
    //     }

    //     EncryptedSessionTokenDTO encryptedSessionTokenDTO = new EncryptedSessionTokenDTO();
    //     encryptedSessionTokenDTO.setSessionToken(encryptedSessionToken.getEncryptedDataBase64());
    //     encryptedSessionTokenDTO.setIvSessionToken(encryptedSessionToken.getIvBase64());
    //     encryptedSessionTokenDTO.setHmacSessionToken(encryptedSessionToken.getHmacBase64());

    //     return encryptedSessionTokenDTO;
    // }

    // public EncryptedDataAesCbc fromEncryptedSessionTokenDto(final EncryptedSessionTokenDTO encryptedSessionTokenDTO) {
    //     if (encryptedSessionTokenDTO == null) {
    //         return null;
    //     }

    //     EncryptedDataAesCbc encryptedDataAESCBC = new EncryptedDataAesCbc();
    //     encryptedDataAESCBC.setEncryptedDataBase64(encryptedSessionTokenDTO.getSessionToken());
    //     encryptedDataAESCBC.setIvBase64(encryptedSessionTokenDTO.getIvSessionToken());
    //     encryptedDataAESCBC.setHmacBase64(encryptedSessionTokenDTO.getHmacSessionToken());

    //     return encryptedDataAESCBC;
    // }
}
