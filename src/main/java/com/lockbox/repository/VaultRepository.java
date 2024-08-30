package com.lockbox.repository;

import com.lockbox.model.Vault;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface VaultRepository extends JpaRepository<Vault, String> {
    List<Vault> findByUserId(String userId);
}
