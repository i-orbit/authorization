package com.inmaytide.orbit.authorization.repository;

import com.inmaytide.orbit.authorization.domain.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * @author inmaytide
 * @since 2024/12/6
 */
@Repository
public interface TenantRepository extends JpaRepository<Tenant, String> {
}
