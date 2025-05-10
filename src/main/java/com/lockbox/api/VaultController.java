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
import com.lockbox.dto.vault.VaultListResponseDTO;
import com.lockbox.dto.vault.VaultRequestDTO;
import com.lockbox.dto.vault.VaultResponseDTO;
import com.lockbox.service.vault.VaultService;
import com.lockbox.utils.ExceptionBuilder;
import com.lockbox.utils.ResponseEntityBuilder;
import com.lockbox.utils.SecurityUtils;

@RestController
@RequestMapping("/api/vaults")
public class VaultController {

    @Autowired
    private VaultService vaultService;

    @Autowired
    private SecurityUtils securityUtils;

    @GetMapping
    public ResponseEntityDTO<VaultListResponseDTO> getAllVaults(
            @RequestParam(name = "page", required = false) Integer page,
            @RequestParam(name = "size", required = false) Integer size) {
        try {
            String userId = securityUtils.getCurrentUserId();
            VaultListResponseDTO vaultListResponse = vaultService.findAllVaultsByUser(userId, page, size);
            ResponseEntityBuilder<VaultListResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(vaultListResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to fetch vaults: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @GetMapping("/{id}")
    public ResponseEntityDTO<VaultResponseDTO> getVaultById(@PathVariable(name = "id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            VaultResponseDTO vaultResponse = vaultService.findVaultById(id, userId);
            ResponseEntityBuilder<VaultResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(vaultResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to fetch vault: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @PostMapping
    public ResponseEntityDTO<VaultResponseDTO> createVault(@RequestBody VaultRequestDTO requestDTO) {
        try {
            String userId = securityUtils.getCurrentUserId();
            VaultResponseDTO vaultResponse = vaultService.createVault(requestDTO, userId);
            ResponseEntityBuilder<VaultResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(vaultResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to create vault: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @PutMapping("/{id}")
    public ResponseEntityDTO<VaultResponseDTO> updateVault(@PathVariable(name = "id") String id,
            @RequestBody VaultRequestDTO requestDTO) {
        try {
            String userId = securityUtils.getCurrentUserId();
            VaultResponseDTO vaultResponse = vaultService.updateVault(id, requestDTO, userId);
            ResponseEntityBuilder<VaultResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(vaultResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to update vault: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntityDTO<Void> deleteVault(@PathVariable(name = "id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            vaultService.deleteVault(id, userId);
            ResponseEntityBuilder<Void> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to delete vault: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @GetMapping("/{id}/credentials/count")
    public ResponseEntityDTO<Integer> getCredentialCountInVault(@PathVariable(name = "id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            int count = vaultService.getCredentialCountInVault(id, userId);
            ResponseEntityBuilder<Integer> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(count).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to get credential count: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }
}