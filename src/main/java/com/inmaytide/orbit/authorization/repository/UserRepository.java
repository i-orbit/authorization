package com.inmaytide.orbit.authorization.repository;

import com.inmaytide.orbit.authorization.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * @author inmaytide
 * @since 2024/12/6
 */
@Repository
public interface UserRepository extends JpaRepository<User, String>, JpaSpecificationExecutor<User> {

    @Query("select u.id from User u where u.employeeNumber = :username or u.username = :username or u.phone = :username or u.email = :username")
    Optional<String> findIdByUsername(@Param("username") String username);

    @Query("select count(u) from User u where u.id in :ids and u.tenantId = :tenantId")
    long countByIdInAndTenantId(@Param("ids") Collection<String> ids, @Param("tenantId") String tenantId);

    @Query(value = """
            select distinct r.code
            from iam.t_user_role ur
            join iam.t_role r on r.id = ur.role_id
            where ur.user_id = :userId
              and r.status = 1
              and r.deleted = 0
            """, nativeQuery = true)
    List<String> findRoleCodesByUserId(@Param("userId") String userId);

    @Query(value = """
            select distinct p.code
            from iam.t_user_role ur
            join iam.t_role r on r.id = ur.role_id
            join iam.t_role_permission rp on rp.role_id = r.id
            join iam.t_permission p on p.id = rp.permission_id
            where ur.user_id = :userId
              and r.status = 1
              and r.deleted = 0
              and p.status = 1
              and p.deleted = 0
            """, nativeQuery = true)
    List<String> findPermissionCodesByUserId(@Param("userId") String userId);

}
