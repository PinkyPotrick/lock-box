package com.lockbox.dto.domain;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;

import com.lockbox.model.Domain;

/**
 * Mapper class for converting between {@link Domain} entities and DTOs.
 */
@Component
public class DomainMapper {

    /**
     * Convert a {@link Domain} entity to a {@link DomainDTO}
     * 
     * @param domain - The Domain entity
     * @return {@link DomainDTO} representation of the domain
     */
    public DomainDTO toDTO(Domain domain) {
        if (domain == null) {
            return null;
        }

        DomainDTO dto = new DomainDTO();
        dto.setId(domain.getId());
        dto.setUserId(domain.getUserId());
        dto.setName(domain.getName());
        dto.setUrl(domain.getUrl());
        dto.setNotes(domain.getNotes());
        dto.setLogo(domain.getLogo());
        dto.setCreatedAt(domain.getCreatedAt());
        dto.setUpdatedAt(domain.getUpdatedAt());

        return dto;
    }

    /**
     * Convert a list of {@link Domain} entities to a list of {@link DomainDTO}s
     * 
     * @param domains - The list of Domain entities
     * @return List of {@link DomainDTO}s
     */
    public List<DomainDTO> toDTOList(List<Domain> domains) {
        if (domains == null) {
            return null;
        }

        return domains.stream().map(this::toDTO).collect(Collectors.toList());
    }

    /**
     * Convert a {@link DomainDTO} to a {@link Domain} entity
     * 
     * @param dto - The DomainDTO
     * @return {@link Domain} entity
     */
    public Domain toEntity(DomainDTO dto) {
        if (dto == null) {
            return null;
        }

        Domain domain = new Domain();
        domain.setUserId(dto.getUserId());
        domain.setName(dto.getName());
        domain.setUrl(dto.getUrl());
        domain.setNotes(dto.getNotes());
        domain.setLogo(dto.getLogo());
        domain.setCreatedAt(dto.getCreatedAt() != null ? dto.getCreatedAt() : LocalDateTime.now());
        domain.setUpdatedAt(dto.getUpdatedAt() != null ? dto.getUpdatedAt() : LocalDateTime.now());

        return domain;
    }

    /**
     * Update a {@link Domain} entity from a {@link DomainDTO}
     * 
     * @param entity - The existing Domain entity
     * @param dto    - The DomainDTO with updated data
     * @return Updated {@link Domain} entity
     */
    public Domain updateEntityFromDTO(Domain entity, DomainDTO dto) {
        if (entity == null || dto == null) {
            return entity;
        }

        if (dto.getName() != null) {
            entity.setName(dto.getName());
        }

        if (dto.getUrl() != null) {
            entity.setUrl(dto.getUrl());
        }

        if (dto.getNotes() != null) {
            entity.setNotes(dto.getNotes());
        }

        if (dto.getLogo() != null) {
            entity.setLogo(dto.getLogo());
        }

        entity.setUpdatedAt(LocalDateTime.now());

        return entity;
    }
}