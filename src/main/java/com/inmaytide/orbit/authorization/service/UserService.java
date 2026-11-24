package com.inmaytide.orbit.authorization.service;

import com.inmaytide.orbit.authorization.domain.User;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;
import java.util.Optional;

/**
 * @author inmaytide
 * @since 2026/11/19
 */
public interface UserService {

    Optional<User> getByUsername(String username);

    List<GrantedAuthority> getAuthorities(String userId);

}
