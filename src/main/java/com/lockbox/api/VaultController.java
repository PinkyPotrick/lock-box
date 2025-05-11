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
import com.lockbox.dto.vault.VaultListResponseDTO;
import com.lockbox.dto.vault.VaultRequestDTO;
import com.lockbox.dto.vault.VaultResponseDTO;
import com.lockbox.service.vault.VaultService;
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
            return new ResponseEntityBuilder<VaultListResponseDTO>().setData(vaultListResponse)
                    .setMessage("Vaults retrieved successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to fetch vaults");
        }
    }

    @GetMapping("/{id}")
    public ResponseEntityDTO<VaultResponseDTO> getVaultById(@PathVariable(name = "id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            VaultResponseDTO vaultResponse = vaultService.findVaultById(id, userId);
            return new ResponseEntityBuilder<VaultResponseDTO>().setData(vaultResponse)
                    .setMessage("Vault retrieved successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to fetch vault");
        }
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntityDTO<VaultResponseDTO> createVault(@RequestBody VaultRequestDTO requestDTO) {
        try {
            String userId = securityUtils.getCurrentUserId();
            VaultResponseDTO vaultResponse = vaultService.createVault(requestDTO, userId);
            return new ResponseEntityBuilder<VaultResponseDTO>().setData(vaultResponse)
                    .setMessage("Vault created successfully").setStatusCode(HttpStatus.CREATED.value()).build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to create vault");
        }
    }

    @PutMapping("/{id}")
    public ResponseEntityDTO<VaultResponseDTO> updateVault(@PathVariable(name = "id") String id,
            @RequestBody VaultRequestDTO requestDTO) {
        try {
            String userId = securityUtils.getCurrentUserId();
            VaultResponseDTO vaultResponse = vaultService.updateVault(id, requestDTO, userId);
            return new ResponseEntityBuilder<VaultResponseDTO>().setData(vaultResponse)
                    .setMessage("Vault updated successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to update vault");
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntityDTO<Void> deleteVault(@PathVariable(name = "id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            vaultService.deleteVault(id, userId);
            return new ResponseEntityBuilder<Void>().setMessage("Vault deleted successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to delete vault");
        }
    }
}