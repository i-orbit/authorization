package com.inmaytide.orbit.authorization.service;

import com.inmaytide.orbit.authorization.domain.Tenant;
import com.inmaytide.orbit.authorization.domain.User;
import com.inmaytide.orbit.authorization.repository.TenantRepository;
import com.inmaytide.orbit.framework.security.SecurityProperties;
import com.inmaytide.orbit.framework.security.domain.ErrorCode;
import com.inmaytide.orbit.framework.security.domain.TenantStatusException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TenantStatusServiceTests {

    private static final String TENANT_ID = "tenant-1";

    @Mock
    private TenantRepository repository;

    private TenantStatusService service;

    private User user;

    @BeforeEach
    void setUp() {
        service = new TenantStatusService(repository, new SecurityProperties());
        user = new User();
        user.setUsername("alice");
        user.setTenantId(TENANT_ID);
    }

    @Test
    void acceptsActiveTenant() {
        when(repository.findByIdAndDeleted(TENANT_ID, 0))
                .thenReturn(Optional.of(tenant(1, Instant.now().plusSeconds(60))));

        assertThatCode(() -> service.validateForLogin(user)).doesNotThrowAnyException();
        assertThat(service.isActive(TENANT_ID)).isTrue();
    }

    @Test
    void rejectsMissingTenant() {
        when(repository.findByIdAndDeleted(TENANT_ID, 0)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.validateForLogin(user))
                .isInstanceOfSatisfying(TenantStatusException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.TENANT_NOT_FOUND));
        assertThat(service.isActive(TENANT_ID)).isFalse();
    }

    @Test
    void rejectsDisabledTenant() {
        when(repository.findByIdAndDeleted(TENANT_ID, 0)).thenReturn(Optional.of(tenant(0, null)));

        assertThatThrownBy(() -> service.validateForLogin(user))
                .isInstanceOfSatisfying(TenantStatusException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.TENANT_DISABLED));
    }

    @Test
    void rejectsExpiredTenant() {
        when(repository.findByIdAndDeleted(TENANT_ID, 0))
                .thenReturn(Optional.of(tenant(1, Instant.now().minusSeconds(60))));

        assertThatThrownBy(() -> service.validateForLogin(user))
                .isInstanceOfSatisfying(TenantStatusException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.TENANT_EXPIRED));
    }

    @Test
    void rejectsUserWithoutTenant() {
        user.setTenantId(null);

        assertThatThrownBy(() -> service.validateForLogin(user))
                .isInstanceOfSatisfying(TenantStatusException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.TENANT_REQUIRED));
    }

    @Test
    void acceptsSuperAdministratorWithoutTenant() {
        user.setTenantId(null);
        user.setUsername("admin");

        assertThatCode(() -> service.validateForLogin(user)).doesNotThrowAnyException();
    }

    @Test
    void treatsMissingTenantClaimAsActiveForPlatformTokens() {
        assertThat(service.isActive(null)).isTrue();
    }

    private static Tenant tenant(Integer status, Instant expiredAt) {
        Tenant tenant = new Tenant();
        tenant.setId(TENANT_ID);
        tenant.setStatus(status);
        tenant.setExpiredAt(expiredAt);
        return tenant;
    }

}
