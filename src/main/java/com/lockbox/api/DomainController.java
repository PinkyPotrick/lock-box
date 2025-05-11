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
import com.lockbox.dto.domain.DomainListResponseDTO;
import com.lockbox.dto.domain.DomainRequestDTO;
import com.lockbox.dto.domain.DomainResponseDTO;
import com.lockbox.service.domain.DomainService;
import com.lockbox.utils.ExceptionBuilder;
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
            ResponseEntityBuilder<DomainListResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(domainListResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to fetch domains: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @GetMapping("/{id}")
    public ResponseEntityDTO<DomainResponseDTO> getDomainById(@PathVariable(name = "id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            DomainResponseDTO domainResponse = domainService.findDomainById(id, userId);
            ResponseEntityBuilder<DomainResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(domainResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to fetch domain: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @PostMapping
    public ResponseEntityDTO<DomainResponseDTO> createDomain(@RequestBody DomainRequestDTO requestDTO) {
        try {
            String userId = securityUtils.getCurrentUserId();
            DomainResponseDTO domainResponse = domainService.createDomain(requestDTO, userId);
            ResponseEntityBuilder<DomainResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(domainResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to create domain: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @PutMapping("/{id}")
    public ResponseEntityDTO<DomainResponseDTO> updateDomain(@PathVariable(name = "id") String id,
            @RequestBody DomainRequestDTO requestDTO) {
        try {
            String userId = securityUtils.getCurrentUserId();
            DomainResponseDTO domainResponse = domainService.updateDomain(id, requestDTO, userId);
            ResponseEntityBuilder<DomainResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(domainResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to update domain: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntityDTO<Void> deleteDomain(@PathVariable(name = "id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            domainService.deleteDomain(id, userId);
            ResponseEntityBuilder<Void> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to delete domain: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @GetMapping("/{id}/credentials/count")
    public ResponseEntityDTO<Integer> getCredentialCountForDomain(@PathVariable(name = "id") String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            int count = domainService.getCredentialCountForDomain(id, userId);
            ResponseEntityBuilder<Integer> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(count).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to get credential count: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }
}