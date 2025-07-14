package com.inmaytide.orbit.authorization.repository;

import com.inmaytide.orbit.authorization.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * @author inmaytide
 * @since 2024/12/12
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, String> {
}
