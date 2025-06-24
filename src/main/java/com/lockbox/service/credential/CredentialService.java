package com.lockbox.service.credential;

import java.util.Optional;

import com.lockbox.dto.credential.CredentialListResponseDTO;
import com.lockbox.dto.credential.CredentialRequestDTO;
import com.lockbox.dto.credential.CredentialResponseDTO;
import com.lockbox.model.Credential;

public interface CredentialService {

    CredentialListResponseDTO findAllCredentialsByVault(String vaultId, String userId, Integer page, Integer size)
            throws Exception;

    CredentialResponseDTO findCredentialById(String id, String vaultId, String userId) throws Exception;

    CredentialResponseDTO createCredential(CredentialRequestDTO requestDTO, String vaultId, String userId)
            throws Exception;

    CredentialResponseDTO updateCredential(String id, CredentialRequestDTO requestDTO, String vaultId, String userId)
            throws Exception;

    void deleteCredential(String id, String vaultId, String userId) throws Exception;

    CredentialResponseDTO toggleFavoriteStatus(String id, String vaultId, String userId) throws Exception;

    CredentialResponseDTO updateLastUsed(String id, String vaultId, String userId) throws Exception;

    CredentialListResponseDTO findCredentialsByDomain(String domainId, String userId) throws Exception;

    CredentialListResponseDTO findFavoriteCredentials(String userId) throws Exception;

    Optional<Credential> findById(String id) throws Exception;

    boolean verifyCredentialIntegrity(String id, String vaultId, String userId) throws Exception;
}