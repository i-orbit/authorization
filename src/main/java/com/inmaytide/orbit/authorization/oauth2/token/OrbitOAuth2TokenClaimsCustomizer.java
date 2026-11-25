package com.inmaytide.orbit.authorization.oauth2.token;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import static com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken.PARAMETER_NAME_PLATFORM;
import static com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken.PARAMETER_NAME_TENANT_ID;

/**
 * Adds Orbit-specific claims to reference access tokens so Spring's standard
 * token introspection provider can expose them without copying its implementation.
 */
public class OrbitOAuth2TokenClaimsCustomizer implements OAuth2TokenCustomizer<OAuth2TokenClaimsContext> {

    private static final String CLAIM_NAME_AUTHORITIES = "authorities";

    private static final String CLAIM_NAME_USERNAME = "username";

    @Override
    public void customize(OAuth2TokenClaimsContext context) {
        Authentication principal = context.getPrincipal();
        context.getClaims()
                .claim(CLAIM_NAME_USERNAME, principal.getName())
                .claim(CLAIM_NAME_AUTHORITIES, principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList());

        OAuth2Authorization authorization = context.getAuthorization();
        if (authorization != null) {
            addAuthorizationAttribute(context, authorization, PARAMETER_NAME_PLATFORM);
            addAuthorizationAttribute(context, authorization, PARAMETER_NAME_TENANT_ID);
        }
    }

    private static void addAuthorizationAttribute(OAuth2TokenClaimsContext context,
                                                  OAuth2Authorization authorization,
                                                  String name) {
        Object value = authorization.getAttribute(name);
        if (value != null) {
            context.getClaims().claim(name, value);
        }
    }
}
