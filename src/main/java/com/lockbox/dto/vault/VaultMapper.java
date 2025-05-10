package com.lockbox.dto.vault;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;

import com.lockbox.model.User;
import com.lockbox.model.Vault;
import com.lockbox.service.vault.VaultClientEncryptionService;

/**
 * Mapper class for converting between {@link Vault} entities and DTOs.
 */
@Component
public class VaultMapper {

    /**
     * Convert a {@link Vault} entity to a {@link VaultDTO}
     * 
     * @param vault - The Vault entity
     * @return {@link VaultDTO} representation of the vault
     */
    public VaultDTO toDTO(Vault vault) {
        if (vault == null) {
            return null;
        }

        VaultDTO dto = new VaultDTO();
        dto.setId(vault.getId());
        dto.setUserId(vault.getUser() != null ? vault.getUser().getId() : null);
        dto.setName(vault.getName());
        dto.setDescription(vault.getDescription());
        dto.setIcon(vault.getIcon());
        dto.setCreatedAt(vault.getCreatedAt());
        dto.setUpdatedAt(vault.getUpdatedAt());

        return dto;
    }

    /**
     * Convert a list of {@link Vault} entities to a list of {@link VaultDTO}s
     * 
     * @param vaults - The list of Vault entities
     * @return List of {@link VaultDTO}s
     */
    public List<VaultDTO> toDTOList(List<Vault> vaults) {
        if (vaults == null) {
            return null;
        }

        return vaults.stream().map(this::toDTO).collect(Collectors.toList());
    }

    /**
     * Convert a {@link Vault} entity to a {@link VaultResponseDTO}
     * 
     * @param vault - The Vault entity
     * @return {@link VaultResponseDTO}
     * @deprecated Use {@link VaultClientEncryptionService#encryptVaultForClient(VaultDTO)} instead
     */
    @Deprecated
    public VaultResponseDTO toResponseDTO(Vault vault) {
        if (vault == null) {
            return null;
        }

        VaultResponseDTO dto = new VaultResponseDTO();
        dto.setId(vault.getId());
        dto.setUserId(vault.getUser() != null ? vault.getUser().getId() : null);
        dto.setIcon(vault.getIcon());
        dto.setCreatedAt(vault.getCreatedAt());
        dto.setUpdatedAt(vault.getUpdatedAt());

        return dto;
    }

    /**
     * Convert a list of {@link Vault} entities to a list of {@link VaultResponseDTO}s
     * 
     * @param vaults - The list of Vault entities
     * @return List of {@link VaultResponseDTO}s
     * @deprecated Use {@link VaultClientEncryptionService#encryptVaultListForClient(List)} instead
     */
    @Deprecated
    public List<VaultResponseDTO> toResponseDTOList(List<Vault> vaults) {
        if (vaults == null) {
            return null;
        }

        return vaults.stream().map(this::toResponseDTO).collect(Collectors.toList());
    }

    /**
     * Convert a {@link VaultDTO} to a {@link Vault} entity
     * 
     * @param dto  - The VaultDTO
     * @param user - The {@link User} entity
     * @return {@link Vault} entity
     */
    public Vault toEntity(VaultDTO dto, User user) {
        if (dto == null) {
            return null;
        }

        Vault vault = new Vault();
        vault.setUser(user);
        vault.setName(dto.getName());
        vault.setDescription(dto.getDescription());
        vault.setIcon(dto.getIcon());
        vault.setCreatedAt(dto.getCreatedAt() != null ? dto.getCreatedAt() : LocalDateTime.now());
        vault.setUpdatedAt(dto.getUpdatedAt() != null ? dto.getUpdatedAt() : LocalDateTime.now());

        return vault;
    }

    /**
     * Update a {@link Vault} entity from a {@link VaultDTO}
     * 
     * @param entity - The existing Vault entity
     * @param dto    - The VaultDTO with updated data
     * @return Updated {@link Vault} entity
     */
    public Vault updateEntityFromDTO(Vault entity, VaultDTO dto) {
        if (entity == null || dto == null) {
            return entity;
        }

        if (dto.getName() != null) {
            entity.setName(dto.getName());
        }

        if (dto.getDescription() != null) {
            entity.setDescription(dto.getDescription());
        }

        if (dto.getIcon() != null) {
            entity.setIcon(dto.getIcon());
        }

        entity.setUpdatedAt(LocalDateTime.now());

        return entity;
    }
}