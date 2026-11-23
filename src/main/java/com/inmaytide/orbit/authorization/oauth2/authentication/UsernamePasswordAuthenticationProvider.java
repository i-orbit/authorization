package com.inmaytide.orbit.authorization.oauth2.authentication;

import com.inmaytide.orbit.authorization.domain.User;
import com.inmaytide.orbit.authorization.oauth2.service.RedisOAuth2AuthorizationService;
import com.inmaytide.orbit.authorization.service.UserService;
import com.inmaytide.orbit.framework.core.enums.ClientPlatform;
import com.inmaytide.orbit.framework.core.enums.UserStatus;
import com.inmaytide.orbit.framework.core.utils.CodecUtils;
import com.inmaytide.orbit.framework.security.SecurityProperties;
import jakarta.annotation.Nonnull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;

import java.util.*;

import static com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken.PARAMETER_NAME_FORCED_REPLACEMENT;
import static com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken.PARAMETER_NAME_PLATFORM;
import static com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken.PARAMETER_NAME_TENANT_ID;

/**
 * @author inmaytide
 * @since 2026/11/19
 */
@Slf4j
@RequiredArgsConstructor
public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {

    private static final String FLAG_LOGIN_WITHOUT_PASSWORD = "__login-without-password";

    private static final Set<String> TRUE_VALUES = Set.of("true", "1", "yes", "y");

    private final UserService userService;

    private final PasswordEncoder passwordEncoder;

    private final SecurityProperties properties;

    private final RedisOAuth2AuthorizationService authorizationService;

    @Override
    public @Nullable Authentication authenticate(@Nonnull Authentication authentication) throws AuthenticationException {
        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
        String rawUsername = token.getUsername();
        if (StringUtils.isBlank(rawUsername)) {
            throw new BadCredentialsException("Username must not be empty");
        }
        boolean withOutPassword = token.getUsername().endsWith(FLAG_LOGIN_WITHOUT_PASSWORD);
        String username = withOutPassword ? Strings.CS.removeEnd(rawUsername, FLAG_LOGIN_WITHOUT_PASSWORD) : rawUsername;
        String password = token.getPassword();
        Optional<User> optionalUser = userService.getByUsername(username);
        if (optionalUser.isEmpty()) {
            log.debug("No user found with username/phone/employeeId/email, {username: {}}", username);
            throw new UsernameNotFoundException("No user found with username/phone/employeeId/email");
        }
        User user = optionalUser.get();
        if (withOutPassword) {
            log.debug("Passwordless login detected, skipping password verification");
        } else {
            String decryptedPassword;
            try {
                decryptedPassword = CodecUtils.decrypt(password);
            } catch (RuntimeException e) {
                log.warn("Failed to decrypt login password, {username: {}}", username);
                throw new BadCredentialsException("Invalid username or password");
            }
            if (!passwordEncoder.matches(decryptedPassword, user.getPassword())) {
                log.warn("The provided password does not match the user, {username: {}, password: PROTECTED)", username);
                throw new BadCredentialsException("Invalid username or password");
            }
        }

        validateUserStatus(user);
        validateConcurrentLogin(user, token.getAdditionalParameters());

        Map<String, Object> additionalParameters = new HashMap<>(token.getAdditionalParameters());
        additionalParameters.put(PARAMETER_NAME_TENANT_ID, user.getTenantId());

        return new UsernamePasswordAuthenticationToken(
                user.getId(),
                user.getPassword(),
                additionalParameters,
                new ArrayList<>()
        );
    }

    private void validateUserStatus(User user) {
        UserStatus status = user.getStatus();
        if (status == null) {
            log.debug("Failed to authenticate since user account status is missing, {userId: {}}", user.getId());
            throw new DisabledException("User is disabled");
        }
        switch (status) {
            case LOCKED -> {
                log.debug("Failed to authenticate since user account is locked, {userId: {}}", user.getId());
                throw new LockedException("User account is locked");
            }
            case DISABLED -> {
                log.debug("Failed to authenticate since user account is disabled, {userId: {}}", user.getId());
                throw new DisabledException("User is disabled");
            }
            default ->
                    log.trace("User account status validation succeeded, {userId: {}, status: {}}", user.getId(), status);
        }
    }

    private void validateConcurrentLogin(User user, Map<String, Object> additionalParameters) {
        if (properties.isAllowUsersToLoginSimultaneously()) {
            return;
        }

        ClientPlatform platform = getPlatform(additionalParameters);
        List<OAuth2Authorization> authorizations = authorizationService.findByPrincipalNameAndPlatform(user.getId(), platform);
        List<OAuth2Authorization> activeAuthorizations = authorizations.stream()
                .filter(UsernamePasswordAuthenticationProvider::isActiveAuthorization)
                .toList();

        authorizations.stream()
                .filter(authorization -> authorization.getAccessToken() != null)
                .filter(authorization -> !isActiveAuthorization(authorization))
                .forEach(authorizationService::remove);

        if (activeAuthorizations.isEmpty()) {
            return;
        }

        if (isForceReplacement(additionalParameters.get(PARAMETER_NAME_FORCED_REPLACEMENT))) {
            authorizations.forEach(authorizationService::remove);
            log.info("Replacing existing login, {userId: {}, platform: {}, replacedSessions: {}}",
                    user.getId(), platform, authorizations.size());
            return;
        }

        log.warn("Rejected concurrent login, {userId: {}, platform: {}}", user.getId(), platform);
        throw new SessionAuthenticationException("User is already logged in elsewhere");
    }

    private ClientPlatform getPlatform(Map<String, Object> additionalParameters) {
        Object value = additionalParameters.get(PARAMETER_NAME_PLATFORM);
        if (!(value instanceof String platformName) || StringUtils.isBlank(platformName)) {
            throw new BadCredentialsException("Login platform must not be empty");
        }
        try {
            return ClientPlatform.valueOf(platformName);
        } catch (IllegalArgumentException e) {
            throw new BadCredentialsException("Unsupported login platform");
        }
    }

    private static boolean isActiveAuthorization(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<org.springframework.security.oauth2.core.OAuth2AccessToken> accessToken =
                authorization.getAccessToken();
        return accessToken != null && accessToken.isActive();
    }

    private static boolean isForceReplacement(Object value) {
        return value != null && TRUE_VALUES.contains(value.toString().trim().toLowerCase());
    }

    @Override
    public boolean supports(@Nonnull Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
