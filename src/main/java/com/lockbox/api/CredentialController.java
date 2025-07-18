package com.lockbox.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.credential.CredentialListResponseDTO;
import com.lockbox.dto.credential.CredentialRequestDTO;
import com.lockbox.dto.credential.CredentialResponseDTO;
import com.lockbox.security.annotation.RequireTotpVerification;
import com.lockbox.service.credential.CredentialService;
import com.lockbox.utils.ResponseEntityBuilder;
import com.lockbox.utils.SecurityUtils;

@RestController
@RequestMapping("/api/vaults/{vaultId}/credentials")
public class CredentialController {

    @Autowired
    private CredentialService credentialService;

    @Autowired
    private SecurityUtils securityUtils;

    @GetMapping
    @RequireTotpVerification(operation = "VIEW_CREDENTIAL")
    public ResponseEntityDTO<CredentialListResponseDTO> getAllCredentials(@PathVariable("vaultId") String vaultId,
            @RequestParam(name = "page", required = false) Integer page,
            @RequestParam(name = "size", required = false) Integer size) {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialListResponseDTO credentialListResponse = credentialService.findAllCredentialsByVault(vaultId,
                    userId, page, size);

            return new ResponseEntityBuilder<CredentialListResponseDTO>().setData(credentialListResponse)
                    .setMessage("Credentials retrieved successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to fetch credentials");
        }
    }

    @GetMapping("/{id}")
    @RequireTotpVerification(operation = "VIEW_CREDENTIAL")
    public ResponseEntityDTO<CredentialResponseDTO> getCredentialById(@PathVariable("vaultId") String vaultId,
            @PathVariable("id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialResponseDTO credential = credentialService.findCredentialById(id, vaultId, userId);

            return new ResponseEntityBuilder<CredentialResponseDTO>().setData(credential)
                    .setMessage("Credential retrieved successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to fetch credential");
        }
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntityDTO<CredentialResponseDTO> createCredential(@PathVariable("vaultId") String vaultId,
            @RequestBody CredentialRequestDTO requestDTO) {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialResponseDTO credential = credentialService.createCredential(requestDTO, vaultId, userId);

            return new ResponseEntityBuilder<CredentialResponseDTO>().setData(credential)
                    .setMessage("Credential created successfully").setStatusCode(HttpStatus.CREATED.value()).build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to create credential");
        }
    }

    @PutMapping("/{id}")
    @RequireTotpVerification(operation = "EDIT_CREDENTIAL")
    public ResponseEntityDTO<CredentialResponseDTO> updateCredential(@PathVariable("vaultId") String vaultId,
            @PathVariable("id") String id, @RequestBody CredentialRequestDTO requestDTO) {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialResponseDTO credential = credentialService.updateCredential(id, requestDTO, vaultId, userId);

            return new ResponseEntityBuilder<CredentialResponseDTO>().setData(credential)
                    .setMessage("Credential updated successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to update credential");
        }
    }

    @DeleteMapping("/{id}")
    @RequireTotpVerification(operation = "DELETE_VAULT")
    public ResponseEntityDTO<Void> deleteCredential(@PathVariable("vaultId") String vaultId,
            @PathVariable("id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            credentialService.deleteCredential(id, vaultId, userId);

            return new ResponseEntityBuilder<Void>().setMessage("Credential deleted successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to delete credential");
        }
    }

    @PutMapping("/{id}/favorite")
    public ResponseEntityDTO<CredentialResponseDTO> toggleFavoriteStatus(@PathVariable("vaultId") String vaultId,
            @PathVariable("id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialResponseDTO credential = credentialService.toggleFavoriteStatus(id, vaultId, userId);

            return new ResponseEntityBuilder<CredentialResponseDTO>().setData(credential)
                    .setMessage("Favorite status updated successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to update favorite status");
        }
    }

    @PutMapping("/{id}/used")
    public ResponseEntityDTO<CredentialResponseDTO> updateLastUsed(@PathVariable("vaultId") String vaultId,
            @PathVariable("id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialResponseDTO credential = credentialService.updateLastUsed(id, vaultId, userId);

            return new ResponseEntityBuilder<CredentialResponseDTO>().setData(credential)
                    .setMessage("Last used timestamp updated successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to update last used timestamp");
        }
    }

    @GetMapping("/{id}/verify")
    public ResponseEntityDTO<Boolean> verifyCredentialIntegrity(@PathVariable("vaultId") String vaultId,
            @PathVariable("id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            boolean verified = credentialService.verifyCredentialIntegrity(id, vaultId, userId);

            String message = verified ? "Credential integrity verified successfully"
                    : "Credential integrity verification failed";

            return new ResponseEntityBuilder<Boolean>().setData(verified).setMessage(message).build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to verify credential integrity");
        }
    }
}