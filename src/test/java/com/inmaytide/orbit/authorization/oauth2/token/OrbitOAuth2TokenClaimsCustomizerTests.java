package com.inmaytide.orbit.authorization.oauth2.token;

import com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OrbitOAuth2TokenClaimsCustomizerTests {

    @Test
    void addsLoginAttributesUsernameAndAuthoritiesToAccessTokenClaims() {
        UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken(
                "user-1",
                null,
                Map.of(
                        UsernamePasswordAuthenticationToken.PARAMETER_NAME_PLATFORM, "WEB",
                        UsernamePasswordAuthenticationToken.PARAMETER_NAME_TENANT_ID, "tenant-1"
                ),
                List.of(new SimpleGrantedAuthority("profile"))
        );
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        when(authorization.getAttribute(UsernamePasswordAuthenticationToken.PARAMETER_NAME_PLATFORM))
                .thenReturn("WEB");
        when(authorization.getAttribute(UsernamePasswordAuthenticationToken.PARAMETER_NAME_TENANT_ID))
                .thenReturn("tenant-1");
        OAuth2TokenClaimsSet.Builder claims = OAuth2TokenClaimsSet.builder();
        OAuth2TokenClaimsContext context = mock(OAuth2TokenClaimsContext.class);
        when(context.getPrincipal()).thenReturn(principal);
        when(context.getAuthorization()).thenReturn(authorization);
        when(context.getClaims()).thenReturn(claims);

        new OrbitOAuth2TokenClaimsCustomizer().customize(context);

        assertThat(claims.build().getClaims())
                .containsEntry("username", "user-1")
                .containsEntry("authorities", List.of("profile"))
                .containsEntry("platform", "WEB")
                .containsEntry("tenantId", "tenant-1");
    }
}
