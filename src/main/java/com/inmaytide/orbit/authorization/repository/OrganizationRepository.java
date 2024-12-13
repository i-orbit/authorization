package com.inmaytide.orbit.authorization.repository;

import com.inmaytide.orbit.authorization.domain.Organization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * @author inmaytide
 * @since 2024/12/12
 */
@Repository
public interface OrganizationRepository extends JpaRepository<Organization, Long> {

    List<Long> findIdsByTenant(Long tenant);

    @Query("select o.id from Organization o")
    List<Long> findIds();

    @Query(nativeQuery = true, value = "select associated from role_association where category = :category and role in (:roleIds)")
    List<Long> findIdsByRoleIds(@Param("category") String category, @Param("roleIds") List<Long> roleIds);
    
}
