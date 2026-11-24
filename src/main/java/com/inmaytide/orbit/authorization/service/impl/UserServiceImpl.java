package com.inmaytide.orbit.authorization.service.impl;

import com.inmaytide.orbit.authorization.domain.User;
import com.inmaytide.orbit.authorization.repository.UserRepository;
import com.inmaytide.orbit.authorization.service.UserService;
import com.inmaytide.orbit.framework.security.SecurityProperties;
import com.inmaytide.orbit.framework.security.SecurityUtils;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author inmaytide
 * @since 2026/11/19
 */
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository repository;

    private final SecurityProperties properties;

    @Override
    public Optional<User> getByUsername(String username) {
        if (StringUtils.isBlank(username)) {
            return Optional.empty();
        }
        return repository.findIdByUsername(username).flatMap(repository::findById);
    }

    @Override
    public List<GrantedAuthority> getAuthorities(String userId) {
        if (StringUtils.isBlank(userId)) {
            return List.of();
        }
        User user = repository.findById(userId).orElse(null);
        if (user == null) {
            return List.of();
        }
        Stream<String> roles = repository.findRoleCodesByUserId(userId).stream()
                .filter(StringUtils::isNotBlank)
                .map(UserServiceImpl::asRoleAuthority);
        Stream<String> permissions = repository.findPermissionCodesByUserId(userId).stream()
                .filter(StringUtils::isNotBlank)
                .map(String::trim);
        List<GrantedAuthority> res = Stream.concat(roles, permissions)
                .distinct()
                .map(SimpleGrantedAuthority::new)
                .map(GrantedAuthority.class::cast)
                .collect(Collectors.toList());
        if (properties.getSuperAdministrator().isEnabled() && Strings.CS.equals(user.getUsername(), properties.getSuperAdministrator().getUsername())) {
            res.add(new SimpleGrantedAuthority(asRoleAuthority(SecurityUtils.ROLE_SUPER_ADMIN)));
        }
        return res;
    }

    private static String asRoleAuthority(String roleCode) {
        String authority = roleCode.trim();
        return authority.startsWith("ROLE_") ? authority : "ROLE_" + authority;
    }

}
