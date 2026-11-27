package com.inmaytide.orbit.authorization.service;

import com.inmaytide.orbit.authorization.domain.Tenant;
import com.inmaytide.orbit.authorization.domain.User;
import com.inmaytide.orbit.authorization.repository.TenantRepository;
import com.inmaytide.orbit.framework.security.SecurityProperties;
import com.inmaytide.orbit.framework.security.domain.SecurityErrorCode;
import com.inmaytide.orbit.framework.security.domain.TenantStatusException;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.springframework.stereotype.Service;

import java.time.Instant;

/**
 * 登录与 token  introspection 时的租户状态校验。
 *
 * @author inmaytide
 * @since 2026/11/25
 */
@Service
@RequiredArgsConstructor
public class TenantStatusService {

    private final TenantRepository repository;

    private final SecurityProperties properties;

    public void validateForLogin(User user) {
        String tenantId = user.getTenantId();
        if (StringUtils.isBlank(tenantId)) {
            if (isSuperAdministrator(user.getUsername())) {
                return;
            }
            throw new TenantStatusException(SecurityErrorCode.TENANT_REQUIRED, "User is not bound to a tenant");
        }
        Tenant tenant = repository.findByIdAndDeleted(tenantId, 0).orElse(null);
        if (tenant == null) {
            throw new TenantStatusException(SecurityErrorCode.TENANT_NOT_FOUND, "Tenant not found");
        }
        if (tenant.getStatus() == null || tenant.getStatus() != 1) {
            throw new TenantStatusException(SecurityErrorCode.TENANT_DISABLED, "Tenant is disabled");
        }
        if (tenant.getExpiredAt() != null && !tenant.getExpiredAt().isAfter(Instant.now())) {
            throw new TenantStatusException(SecurityErrorCode.TENANT_EXPIRED, "Tenant license has expired");
        }
    }

    public boolean isActive(String tenantId) {
        if (StringUtils.isBlank(tenantId)) {
            return true;
        }
        Tenant tenant = repository.findByIdAndDeleted(tenantId, 0).orElse(null);
        return tenant != null
                && tenant.getStatus() != null
                && tenant.getStatus() == 1
                && (tenant.getExpiredAt() == null || tenant.getExpiredAt().isAfter(Instant.now()));
    }

    private boolean isSuperAdministrator(String username) {
        return properties.getSuperAdministrator().isEnabled()
                && Strings.CS.equals(username, properties.getSuperAdministrator().getUsername());
    }

}
