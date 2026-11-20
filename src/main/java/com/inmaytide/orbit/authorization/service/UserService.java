package com.inmaytide.orbit.authorization.service;

import com.inmaytide.orbit.authorization.domain.User;

import java.util.Optional;

/**
 * @author inmaytide
 * @since 2026/11/19
 */
public interface UserService {

    Optional<User> getByUsername(String username);

}
