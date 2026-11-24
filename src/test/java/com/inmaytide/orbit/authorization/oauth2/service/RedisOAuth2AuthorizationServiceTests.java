package com.inmaytide.orbit.authorization.oauth2.service;

import com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken;
import com.inmaytide.orbit.framework.core.enums.ClientPlatform;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RedisOAuth2AuthorizationServiceTests {

    @Mock
    private RedisTemplate<String, OAuth2Authorization> redisTemplate;

    private RedisOAuth2AuthorizationService authorizationService;

    @BeforeEach
    void setUp() {
        authorizationService = new RedisOAuth2AuthorizationService(mock(RedisConnectionFactory.class));
        ReflectionTestUtils.setField(authorizationService, "redisTemplate", redisTemplate);
        when(redisTemplate.keys(anyString())).thenReturn(Set.of());
    }

    @Test
    void savesPlatformFromLoginAuthenticationAsAuthorizationAttribute() {
        UsernamePasswordAuthenticationToken principal = principal();
        OAuth2Authorization authorization = authorization(principal);

        authorizationService.save(authorization);

        assertThat(authorizationService.findByPrincipalNameAndPlatform(
                principal.getName(), ClientPlatform.WEB))
                .singleElement()
                .extracting(saved -> saved.getAttribute(
                        UsernamePasswordAuthenticationToken.PARAMETER_NAME_PLATFORM))
                .isEqualTo(ClientPlatform.WEB.name());
    }

    @Test
    void keepsAuthoritiesInsideTheLoginPrincipal() {
        UsernamePasswordAuthenticationToken principal = principal(List.of(
                new SimpleGrantedAuthority("ROLE_ADMIN"),
                new SimpleGrantedAuthority("user:read")
        ));
        OAuth2Authorization authorization = authorization(principal);

        authorizationService.save(authorization);

        assertThat(authorizationService.findByPrincipalNameAndPlatform(
                principal.getName(), ClientPlatform.WEB))
                .singleElement()
                .satisfies(saved -> assertThat(saved.<UsernamePasswordAuthenticationToken>getAttribute(
                        Principal.class.getName()).getAuthorities())
                        .extracting(GrantedAuthority::getAuthority)
                        .containsExactly("ROLE_ADMIN", "user:read"));
    }

    @Test
    void removesInitializedAuthorizationByItsOriginalInstance() {
        UsernamePasswordAuthenticationToken principal = principal();
        OAuth2Authorization authorization = authorization(principal);

        authorizationService.save(authorization);
        authorizationService.remove(authorization);

        assertThat(authorizationService.findByPrincipalNameAndPlatform(
                principal.getName(), ClientPlatform.WEB))
                .isEmpty();
    }

    private static UsernamePasswordAuthenticationToken principal() {
        return principal(List.of());
    }

    private static UsernamePasswordAuthenticationToken principal(List<GrantedAuthority> authorities) {
        return new UsernamePasswordAuthenticationToken(
                "user-1",
                null,
                Map.of(UsernamePasswordAuthenticationToken.PARAMETER_NAME_PLATFORM, ClientPlatform.WEB.name()),
                authorities
        );
    }

    private static OAuth2Authorization authorization(UsernamePasswordAuthenticationToken principal) {
        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClient.getId()).thenReturn("client-1");
        return OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(principal.getName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(Principal.class.getName(), principal)
                .build();
    }
}
