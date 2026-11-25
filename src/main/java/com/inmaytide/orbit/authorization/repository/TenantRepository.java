package com.inmaytide.orbit.authorization.repository;

import com.inmaytide.orbit.authorization.domain.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * @author inmaytide
 * @since 2026/11/25
 */
@Repository
public interface TenantRepository extends JpaRepository<Tenant, String> {

    Optional<Tenant> findByIdAndDeleted(String id, Integer deleted);

}
