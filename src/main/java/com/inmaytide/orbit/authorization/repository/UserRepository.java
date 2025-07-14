package com.inmaytide.orbit.authorization.repository;

import com.inmaytide.orbit.authorization.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * @author inmaytide
 * @since 2024/12/6
 */
@Repository
public interface UserRepository extends JpaRepository<User, String>, JpaSpecificationExecutor<User> {

    @Query("select u.id from User u where u.telephoneNumber = :username or u.loginName = :username or u.employeeId = :username or u.email = :username")
    Optional<String> findIdByUsername(@Param("username") String username);

}
