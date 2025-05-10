package com.lockbox.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.credential.CredentialListResponseDTO;
import com.lockbox.dto.credential.CredentialRequestDTO;
import com.lockbox.dto.credential.CredentialResponseDTO;
import com.lockbox.service.credential.CredentialService;
import com.lockbox.utils.ExceptionBuilder;
import com.lockbox.utils.ResponseEntityBuilder;
import com.lockbox.utils.SecurityUtils;

@RestController
@RequestMapping("/api/credentials")
public class CredentialController {

    @Autowired
    private CredentialService credentialService;

    @Autowired
    private SecurityUtils securityUtils;

    @GetMapping
    public ResponseEntityDTO<CredentialListResponseDTO> getAllCredentials() {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialListResponseDTO credentialListResponse = credentialService.findAllCredentialsByUser(userId);
            ResponseEntityBuilder<CredentialListResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(credentialListResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to fetch credentials").throwInternalServerErrorException();
            return null;
        }
    }

    @GetMapping("/{id}")
    public ResponseEntityDTO<CredentialResponseDTO> getCredentialById(@PathVariable String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialResponseDTO credentialResponse = credentialService.findCredentialById(id, userId);
            ResponseEntityBuilder<CredentialResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(credentialResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to fetch credential").throwInternalServerErrorException();
            return null;
        }
    }

    @PostMapping
    public ResponseEntityDTO<CredentialResponseDTO> createCredential(@RequestBody CredentialRequestDTO requestDTO) {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialResponseDTO credentialResponse = credentialService.createCredential(requestDTO, userId);
            ResponseEntityBuilder<CredentialResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(credentialResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to create credential").throwInternalServerErrorException();
            return null;
        }
    }

    @PutMapping("/{id}")
    public ResponseEntityDTO<CredentialResponseDTO> updateCredential(@PathVariable String id,
            @RequestBody CredentialRequestDTO requestDTO) {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialResponseDTO credentialResponse = credentialService.updateCredential(id, requestDTO, userId);
            ResponseEntityBuilder<CredentialResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(credentialResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to update credential").throwInternalServerErrorException();
            return null;
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntityDTO<Void> deleteCredential(@PathVariable String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            credentialService.deleteCredential(id, userId);
            ResponseEntityBuilder<Void> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to delete credential").throwInternalServerErrorException();
            return null;
        }
    }

    @PutMapping("/{id}/favorite")
    public ResponseEntityDTO<CredentialResponseDTO> toggleFavorite(@PathVariable String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialResponseDTO credentialResponse = credentialService.toggleFavorite(id, userId);
            ResponseEntityBuilder<CredentialResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(credentialResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to update favorite status")
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @GetMapping("/domain/{domainId}")
    public ResponseEntityDTO<CredentialListResponseDTO> getCredentialsByDomain(@PathVariable String domainId) {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialListResponseDTO credentialResponse = credentialService.findCredentialsByDomain(domainId, userId);
            ResponseEntityBuilder<CredentialListResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(credentialResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to fetch credentials").throwInternalServerErrorException();
            return null;
        }
    }

    @GetMapping("/vault/{vaultId}")
    public ResponseEntityDTO<CredentialListResponseDTO> getCredentialsByVault(@PathVariable String vaultId) {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialListResponseDTO credentialResponse = credentialService.findCredentialsByVault(vaultId, userId);
            ResponseEntityBuilder<CredentialListResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(credentialResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to fetch credentials").throwInternalServerErrorException();
            return null;
        }
    }

    @GetMapping("/favorites")
    public ResponseEntityDTO<CredentialListResponseDTO> getFavoriteCredentials() {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialListResponseDTO credentialResponse = credentialService.findFavoriteCredentials(userId);
            ResponseEntityBuilder<CredentialListResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(credentialResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to fetch favorite credentials")
                    .throwInternalServerErrorException();
            return null;
        }
    }
}