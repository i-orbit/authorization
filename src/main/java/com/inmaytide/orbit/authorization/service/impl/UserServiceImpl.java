package com.inmaytide.orbit.authorization.service.impl;

import com.inmaytide.orbit.authorization.domain.User;
import com.inmaytide.orbit.authorization.repository.UserRepository;
import com.inmaytide.orbit.authorization.service.UserService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * @author inmaytide
 * @since 2026/11/19
 */
@Service
public class UserServiceImpl implements UserService {

    private final UserRepository repository;

    public UserServiceImpl(UserRepository repository) {
        this.repository = repository;
    }

    @Override
    public Optional<User> getByUsername(String username) {
        if (StringUtils.isBlank(username)) {
            return Optional.empty();
        }
        return repository.findIdByUsername(username).flatMap(repository::findById);
    }

}
