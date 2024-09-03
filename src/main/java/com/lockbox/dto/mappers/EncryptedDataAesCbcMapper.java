package com.lockbox.dto.mappers;

import com.lockbox.dto.EncryptedDataAesCbcDTO;
import com.lockbox.model.EncryptedDataAesCbc;

public class EncryptedDataAesCbcMapper {

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
}
