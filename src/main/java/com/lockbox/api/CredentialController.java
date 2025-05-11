package com.lockbox.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
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
@RequestMapping("/api/vaults/{vaultId}/credentials")
public class CredentialController {

    @Autowired
    private CredentialService credentialService;

    @Autowired
    private SecurityUtils securityUtils;

    @GetMapping
    public ResponseEntityDTO<CredentialListResponseDTO> getAllCredentials(@PathVariable("vaultId") String vaultId,
            @RequestParam(name = "page", required = false) Integer page,
            @RequestParam(name = "size", required = false) Integer size,
            @RequestParam(name = "sort", required = false) String sort,
            @RequestParam(name = "direction", required = false) String direction) {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialListResponseDTO credentialListResponse = credentialService.findAllCredentialsByVault(vaultId,
                    userId, page, size, sort, direction);

            ResponseEntityBuilder<CredentialListResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(credentialListResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to fetch credentials: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @GetMapping("/{id}")
    public ResponseEntityDTO<CredentialResponseDTO> getCredentialById(@PathVariable("vaultId") String vaultId,
            @PathVariable("id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialResponseDTO credential = credentialService.findCredentialById(id, vaultId, userId);

            ResponseEntityBuilder<CredentialResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(credential).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to fetch credential: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @PostMapping
    public ResponseEntityDTO<CredentialResponseDTO> createCredential(@PathVariable("vaultId") String vaultId,
            @RequestBody CredentialRequestDTO requestDTO) {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialResponseDTO credential = credentialService.createCredential(requestDTO, vaultId, userId);

            ResponseEntityBuilder<CredentialResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(credential).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to create credential: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @PutMapping("/{id}")
    public ResponseEntityDTO<CredentialResponseDTO> updateCredential(@PathVariable("vaultId") String vaultId,
            @PathVariable("id") String id, @RequestBody CredentialRequestDTO requestDTO) {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialResponseDTO credential = credentialService.updateCredential(id, requestDTO, vaultId, userId);

            ResponseEntityBuilder<CredentialResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(credential).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to update credential: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntityDTO<Void> deleteCredential(@PathVariable("vaultId") String vaultId,
            @PathVariable("id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            credentialService.deleteCredential(id, vaultId, userId);

            ResponseEntityBuilder<Void> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to delete credential: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @PutMapping("/{id}/favorite")
    public ResponseEntityDTO<CredentialResponseDTO> toggleFavoriteStatus(@PathVariable("vaultId") String vaultId,
            @PathVariable("id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialResponseDTO credential = credentialService.toggleFavoriteStatus(id, vaultId, userId);

            ResponseEntityBuilder<CredentialResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(credential).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to update favorite status: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @PutMapping("/{id}/used")
    public ResponseEntityDTO<CredentialResponseDTO> updateLastUsed(@PathVariable("vaultId") String vaultId,
            @PathVariable("id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            CredentialResponseDTO credential = credentialService.updateLastUsed(id, vaultId, userId);

            ResponseEntityBuilder<CredentialResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(credential).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to update last used timestamp: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }
}