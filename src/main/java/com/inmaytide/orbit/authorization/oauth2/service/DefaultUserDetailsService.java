package com.inmaytide.orbit.authorization.oauth2.service;

import com.inmaytide.exception.web.AccessDeniedException;
import com.inmaytide.exception.web.BadCredentialsException;
import com.inmaytide.orbit.authorization.configuration.ApplicationProperties;
import com.inmaytide.orbit.authorization.configuration.ErrorCode;
import com.inmaytide.orbit.authorization.domain.Tenant;
import com.inmaytide.orbit.authorization.repository.TenantRepository;
import com.inmaytide.orbit.authorization.service.UserActivityService;
import com.inmaytide.orbit.commons.business.SystemUserService;
import com.inmaytide.orbit.commons.constants.Bool;
import com.inmaytide.orbit.commons.constants.Constants;
import com.inmaytide.orbit.commons.constants.TenantStatus;
import com.inmaytide.orbit.commons.constants.UserStatus;
import com.inmaytide.orbit.commons.domain.SystemUser;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author inmaytide
 * @since 2023/04/29
 */
@Component
public class DefaultUserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    public static final String ROLE_PREFIX = "ROLE_";

    private final SystemUserService userService;

    private final PasswordEncoder passwordEncoder;

    private final TenantRepository tenantRepository;

    private final UserActivityService userActivityService;

    private final ApplicationProperties props;

    public DefaultUserDetailsService(SystemUserService userService, PasswordEncoder passwordEncoder, TenantRepository tenantRepository, UserActivityService userActivityService, ApplicationProperties props) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.tenantRepository = tenantRepository;
        this.userActivityService = userActivityService;
        this.props = props;
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        boolean withoutPassword = username.endsWith(Constants.Markers.LOGIN_WITHOUT_PASSWORD);
        final String loginName = withoutPassword ? StringUtils.removeEnd(username, Constants.Markers.LOGIN_WITHOUT_PASSWORD) : username;
        SystemUser user = userService.findByUsername(loginName).orElseThrow(() -> new BadCredentialsException(ErrorCode.E_0x02100001, loginName));
        validateTenant(user);
        return org.springframework.security.core.userdetails.User.withUsername(String.valueOf(user.getId()))
                .password(withoutPassword ? passwordEncoder.encode(Constants.Markers.LOGIN_WITHOUT_PASSWORD) : user.getPassword())
                .accountLocked(user.getStatus() == UserStatus.LOCKED)
                .disabled(user.getStatus() == UserStatus.DISABLED)
                .authorities(createAuthoritiesWithUser(user))
                .build();
    }

    /**
     * 验证登录用户租户有效性
     * <ul>
     *     <li>用户租户为默认内置租户 - 允许登录</li>
     *     <li>用户租户在系统中已禁用/已删除/不存在 - 禁止登录</li>
     *     <li>用户租户已过期 - 仅允许租户管理员且最大<code>${application.restricted-tenant-maximum-online-users}</code>个用户登录</li>
     * </ul>
     *
     * @param user 登录用户信息
     */
    private void validateTenant(SystemUser user) {
        // 如果用户租户为系统内置默认租户, 该租户为系统超级管理员专用
        if (Objects.equals(user.getTenant(), Constants.Markers.NON_TENANT_ID)) {
            return;
        }
        Optional<Tenant> op = tenantRepository.findById(user.getTenant());
        // 用户所属租户不存在
        if (op.isEmpty()) {
            throw new AccessDeniedException(ErrorCode.E_0x02100002);
        }
        Tenant tenant = op.get();
        // 用户所属租户已禁用
        if (tenant.getStatus() == TenantStatus.DISABLED) {
            throw new AccessDeniedException(ErrorCode.E_0x02100003);
        }
        // 用户所属租户已过期
        if (tenant.getStatus() == TenantStatus.EXPIRED) {
            if (user.getIsTenantAdministrator() != Bool.Y) {
                throw new AccessDeniedException(ErrorCode.E_0x02100004);
            }
            if (userActivityService.getNumberOfOnlineUsers(tenant.getId()) >= props.getRestrictedTenantMaximumOnlineUsers()) {
                throw new AccessDeniedException(ErrorCode.E_0x02100004);
            }
        }
    }

    private List<GrantedAuthority> createAuthoritiesWithUser(SystemUser user) {
        return Stream.concat(user.getPermission().getRoles().stream().map(e -> !e.startsWith(ROLE_PREFIX) ? ROLE_PREFIX + e : e), user.getPermission().getAuthorities().stream())
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

}
