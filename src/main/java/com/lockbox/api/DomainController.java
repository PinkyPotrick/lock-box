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
import com.lockbox.dto.domain.DomainListResponseDTO;
import com.lockbox.dto.domain.DomainRequestDTO;
import com.lockbox.dto.domain.DomainResponseDTO;
import com.lockbox.service.domain.DomainService;
import com.lockbox.utils.ResponseEntityBuilder;
import com.lockbox.utils.SecurityUtils;

@RestController
@RequestMapping("/api/domains")
public class DomainController {

    @Autowired
    private DomainService domainService;

    @Autowired
    private SecurityUtils securityUtils;

    @GetMapping
    public ResponseEntityDTO<DomainListResponseDTO> getAllDomains(
            @RequestParam(name = "page", required = false) Integer page,
            @RequestParam(name = "size", required = false) Integer size) {
        try {
            String userId = securityUtils.getCurrentUserId();
            DomainListResponseDTO domainListResponse = domainService.findAllDomainsByUser(userId, page, size);
            return new ResponseEntityBuilder<DomainListResponseDTO>().setData(domainListResponse)
                    .setMessage("Domains retrieved successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to fetch domains");
        }
    }

    @GetMapping("/{id}")
    public ResponseEntityDTO<DomainResponseDTO> getDomainById(@PathVariable(name = "id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            DomainResponseDTO domainResponse = domainService.findDomainById(id, userId);
            return new ResponseEntityBuilder<DomainResponseDTO>().setData(domainResponse)
                    .setMessage("Domain retrieved successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to fetch domain");
        }
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntityDTO<DomainResponseDTO> createDomain(@RequestBody DomainRequestDTO requestDTO) {
        try {
            String userId = securityUtils.getCurrentUserId();
            DomainResponseDTO domainResponse = domainService.createDomain(requestDTO, userId);
            return new ResponseEntityBuilder<DomainResponseDTO>().setData(domainResponse)
                    .setMessage("Domain created successfully").setStatusCode(HttpStatus.CREATED.value()).build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to create domain");
        }
    }

    @PutMapping("/{id}")
    public ResponseEntityDTO<DomainResponseDTO> updateDomain(@PathVariable(name = "id") String id,
            @RequestBody DomainRequestDTO requestDTO) {
        try {
            String userId = securityUtils.getCurrentUserId();
            DomainResponseDTO domainResponse = domainService.updateDomain(id, requestDTO, userId);
            return new ResponseEntityBuilder<DomainResponseDTO>().setData(domainResponse)
                    .setMessage("Domain updated successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to update domain");
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntityDTO<Void> deleteDomain(@PathVariable(name = "id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            domainService.deleteDomain(id, userId);
            return new ResponseEntityBuilder<Void>().setMessage("Domain deleted successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to delete domain");
        }
    }

    @GetMapping("/{id}/credentials/count")
    public ResponseEntityDTO<Integer> getCredentialCountForDomain(@PathVariable(name = "id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            int count = domainService.getCredentialCountForDomain(id, userId);
            return new ResponseEntityBuilder<Integer>().setData(count)
                    .setMessage("Credential count retrieved successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to get credential count");
        }
    }
}