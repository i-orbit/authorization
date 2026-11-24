package com.inmaytide.orbit.authorization.service.impl;

import com.inmaytide.orbit.authorization.domain.User;
import com.inmaytide.orbit.authorization.repository.UserRepository;
import com.inmaytide.orbit.framework.security.SecurityProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTests {

    private static final String USER_ID = "user-1";

    @Mock
    private UserRepository repository;

    @Test
    void buildsDistinctRoleAndPermissionAuthorities() {
        User user = new User();
        user.setId(USER_ID);
        user.setUsername("alice");
        when(repository.findById(USER_ID)).thenReturn(Optional.of(user));
        when(repository.findRoleCodesByUserId(USER_ID))
                .thenReturn(Arrays.asList("SUPER_ADMIN", "ROLE_TENANT_ADMIN", " ", null));
        when(repository.findPermissionCodesByUserId(USER_ID))
                .thenReturn(Arrays.asList("user:read", "user:write", "user:read", " "));
        UserServiceImpl service = new UserServiceImpl(repository, new SecurityProperties());

        List<GrantedAuthority> authorities = service.getAuthorities(USER_ID);

        assertThat(authorities)
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_SUPER_ADMIN", "ROLE_TENANT_ADMIN", "user:read", "user:write");
    }

    @Test
    void returnsEmptyAuthoritiesForBlankUserId() {
        UserServiceImpl service = new UserServiceImpl(repository, new SecurityProperties());

        assertThat(service.getAuthorities(" ")).isEmpty();
        verifyNoInteractions(repository);
    }

}
