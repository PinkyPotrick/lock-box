package com.lockbox.service.credential;

import java.util.List;

import com.lockbox.dto.credential.CredentialDTO;
import com.lockbox.dto.credential.CredentialListResponseDTO;
import com.lockbox.dto.credential.CredentialRequestDTO;
import com.lockbox.dto.credential.CredentialResponseDTO;
import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;

public interface CredentialClientEncryptionService {

    CredentialResponseDTO encryptCredentialForClient(CredentialDTO credentialDTO) throws Exception;

    CredentialListResponseDTO encryptCredentialListForClient(List<CredentialDTO> credentialDTOs, String vaultName)
            throws Exception;

    CredentialDTO decryptCredentialFromClient(CredentialRequestDTO requestDTO) throws Exception;

    EncryptedDataAesCbcDTO encryptVaultName(String vaultName, String helperAesKey) throws Exception;
}