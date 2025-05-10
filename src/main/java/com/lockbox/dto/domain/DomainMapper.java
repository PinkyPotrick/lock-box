package com.lockbox.dto.domain;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;

import com.lockbox.model.Domain;

@Component
public class DomainMapper {

    /**
     * Convert a Domain entity to a DomainResponseDTO
     * 
     * @param domain The Domain entity
     * @return DomainResponseDTO
     */
    public DomainResponseDTO toResponseDTO(Domain domain) {
        if (domain == null) {
            return null;
        }

        DomainResponseDTO dto = new DomainResponseDTO();
        dto.setId(domain.getId());
        dto.setUserId(domain.getUserId());
        dto.setName(domain.getName());
        dto.setUrl(domain.getUrl());
        dto.setLogo(domain.getLogo());
        dto.setNotes(domain.getNotes());
        dto.setCreatedAt(domain.getCreatedAt());
        dto.setUpdatedAt(domain.getUpdatedAt());

        return dto;
    }

    /**
     * Convert a list of Domain entities to a list of DomainResponseDTOs
     * 
     * @param domains The list of Domain entities
     * @return List of DomainResponseDTOs
     */
    public List<DomainResponseDTO> toResponseDTOList(List<Domain> domains) {
        if (domains == null) {
            return null;
        }

        return domains.stream().map(this::toResponseDTO).collect(Collectors.toList());
    }

    /**
     * Convert a DomainRequestDTO to a Domain entity
     * 
     * @param dto The DomainRequestDTO
     * @return Domain entity
     */
    public Domain toEntity(DomainRequestDTO dto) {
        if (dto == null) {
            return null;
        }

        Domain domain = new Domain();
        domain.setUserId(dto.getUserId());
        domain.setName(dto.getName());
        domain.setUrl(dto.getUrl());
        domain.setLogo(dto.getLogo());
        domain.setNotes(dto.getNotes());
        domain.setCreatedAt(LocalDateTime.now());
        domain.setUpdatedAt(LocalDateTime.now());

        return domain;
    }

    /**
     * Update a Domain entity from a DomainRequestDTO
     * 
     * @param entity The existing Domain entity
     * @param dto    The DomainRequestDTO with updated data
     * @return Updated Domain entity
     */
    public Domain updateEntityFromDTO(Domain entity, DomainRequestDTO dto) {
        if (entity == null || dto == null) {
            return entity;
        }

        if (dto.getUserId() != null) {
            entity.setUserId(dto.getUserId());
        }

        if (dto.getName() != null) {
            entity.setName(dto.getName());
        }

        if (dto.getUrl() != null) {
            entity.setUrl(dto.getUrl());
        }

        if (dto.getLogo() != null) {
            entity.setLogo(dto.getLogo());
        }

        if (dto.getNotes() != null) {
            entity.setNotes(dto.getNotes());
        }

        entity.setUpdatedAt(LocalDateTime.now());

        return entity;
    }
}