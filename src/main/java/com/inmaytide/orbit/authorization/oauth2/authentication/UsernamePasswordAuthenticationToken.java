package com.inmaytide.orbit.authorization.oauth2.authentication;

import com.inmaytide.orbit.authorization.domain.LoginRequest;
import lombok.Getter;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author inmaytide
 * @since 2026/11/19
 */
@Getter
public class UsernamePasswordAuthenticationToken extends AbstractAuthenticationToken {

    public static final String PARAMETER_NAME_PLATFORM = "platform";

    public static final String PARAMETER_NAME_FORCE_REPLACEMENT = "forceReplacement";

    private final String username;

    private String password;

    private final Map<String, Object> additionalParameters;

    public UsernamePasswordAuthenticationToken(LoginRequest body) {
        super(Collections.emptyList());
        this.username = body.getUsername();
        this.password = body.getPassword();
        this.additionalParameters = new HashMap<>();
        this.additionalParameters.put(PARAMETER_NAME_PLATFORM, body.getPlatform() == null ? null : body.getPlatform().name());
        this.additionalParameters.put(PARAMETER_NAME_FORCE_REPLACEMENT, body.isForceReplacement());
        setAuthenticated(false);
    }

    public UsernamePasswordAuthenticationToken(String username, String password, Map<String, Object> additionalParameters, List<GrantedAuthority> authorities) {
        super(authorities);
        this.username = username;
        this.password = password;
        this.additionalParameters = additionalParameters;
        setAuthenticated(true);
    }

    @Override
    public @Nullable Object getCredentials() {
        return password;
    }

    @Override
    public @Nullable Object getPrincipal() {
        return username;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.password = null;
    }
}
