package com.inmaytide.orbit.authorization.service;

import com.inmaytide.orbit.commons.business.SystemUserService;
import com.inmaytide.orbit.commons.domain.SystemUser;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import java.io.Serializable;
import java.util.Optional;

/**
 * @author inmaytide
 * @since 2024/12/6
 */
@Primary
@Service
public class DefaultSystemUserService implements SystemUserService {

    @Override
    public SystemUser get(Serializable id) {
        return null;
    }

    @Override
    public Optional<SystemUser> findByUsername(String username) {
        return Optional.empty();
    }

}
