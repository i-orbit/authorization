package com.inmaytide.orbit.authorization.oauth2.service;

import com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken;
import com.inmaytide.orbit.framework.core.enums.ClientPlatform;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.SetOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken.PARAMETER_NAME_LOGIN_SESSION_TOKEN;
import static com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken.PARAMETER_NAME_PLATFORM;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RedisOAuth2AuthorizationServiceTests {

    private static final String USER_ID = "user-1";

    private static final String SESSION_TOKEN = "login-session-token";

    private static final String STATE = "state-value";

    private static final Duration VALIDITY = Duration.ofMinutes(30);

    @Mock
    private RedisTemplate<String, OAuth2Authorization> redisTemplate;

    @Mock
    private StringRedisTemplate indexRedisTemplate;

    @Mock
    private ValueOperations<String, OAuth2Authorization> authorizationValues;

    @Mock
    private ValueOperations<String, String> indexValues;

    @Mock
    private SetOperations<String, String> indexSets;

    @Mock
    private LoginAuthenticationTokenService loginAuthenticationTokenService;

    private RedisOAuth2AuthorizationService authorizationService;

    @BeforeEach
    void setUp() {
        lenient().when(redisTemplate.opsForValue()).thenReturn(authorizationValues);
        lenient().when(indexRedisTemplate.opsForValue()).thenReturn(indexValues);
        lenient().when(indexRedisTemplate.opsForSet()).thenReturn(indexSets);
        lenient().when(loginAuthenticationTokenService.getValidity()).thenReturn(VALIDITY);
        authorizationService = new RedisOAuth2AuthorizationService(
                redisTemplate, indexRedisTemplate, loginAuthenticationTokenService);
    }

    @Test
    void persistsCompleteAuthorizationWithLoginAttributesAndIndexes() {
        OAuth2Authorization authorization = rawCompleteAuthorization(principal(), STATE);

        authorizationService.save(authorization);

        ArgumentCaptor<OAuth2Authorization> saved = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(authorizationValues).set(
                eq("orbit:authorization:auth:" + authorization.getId()), saved.capture(), eq(VALIDITY));
        OAuth2Authorization enriched = saved.getValue();
        assertThat(enriched.<String>getAttribute(PARAMETER_NAME_PLATFORM)).isEqualTo(ClientPlatform.WEB.name());
        assertThat(enriched.<String>getAttribute(PARAMETER_NAME_LOGIN_SESSION_TOKEN)).isEqualTo(SESSION_TOKEN);

        verify(indexValues).set("orbit:authorization:token:access-token", authorization.getId(), VALIDITY);
        verify(indexValues).set("orbit:authorization:token:" + STATE, authorization.getId(), VALIDITY);
        verify(indexSets).add("orbit:authorization:principal:" + USER_ID + ":WEB", authorization.getId());
        verify(indexSets).add("orbit:authorization:session:" + SESSION_TOKEN, authorization.getId());
    }

    @Test
    void persistsInitializedAuthorizationToRedisForMultiInstanceDeployment() {
        OAuth2Authorization authorization = authorization(principal(), STATE);

        authorizationService.save(authorization);

        verify(authorizationValues).set(
                eq("orbit:authorization:auth:" + authorization.getId()),
                any(OAuth2Authorization.class),
                eq(Duration.ofMinutes(10)));
        verify(indexValues).set("orbit:authorization:token:" + STATE, authorization.getId(), Duration.ofMinutes(10));
    }

    @Test
    void keepsAuthoritiesInsideTheLoginPrincipal() {
        OAuth2Authorization authorization = authorization(principal(List.of(
                new SimpleGrantedAuthority("ROLE_ADMIN"),
                new SimpleGrantedAuthority("user:read")
        )), STATE);

        authorizationService.save(authorization);

        ArgumentCaptor<OAuth2Authorization> saved = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(authorizationValues).set(anyString(), saved.capture(), any(Duration.class));
        assertThat(saved.getValue().<UsernamePasswordAuthenticationToken>getAttribute(
                        Principal.class.getName()).getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_ADMIN", "user:read");
    }

    @Test
    void findsAuthorizationByTokenThroughIndexWithoutScanningRedisKeys() {
        OAuth2Authorization authorization = completeAuthorization(principal(), STATE);
        when(indexValues.get("orbit:authorization:token:access-token")).thenReturn(authorization.getId());
        when(authorizationValues.get("orbit:authorization:auth:" + authorization.getId())).thenReturn(authorization);

        OAuth2Authorization found = authorizationService.findByToken(
                "access-token", OAuth2TokenType.ACCESS_TOKEN);

        assertThat(found).isSameAs(authorization);
        verify(redisTemplate, never()).keys(anyString());
        verify(loginAuthenticationTokenService).renew(SESSION_TOKEN);
        verify(indexRedisTemplate).expire("orbit:authorization:session:" + SESSION_TOKEN, VALIDITY);
    }

    @Test
    void returnsNullWithoutDeletingIndexWhenTokenTypeHintDoesNotMatch() {
        OAuth2Authorization authorization = completeAuthorization(principal(), STATE);
        when(indexValues.get("orbit:authorization:token:state-value")).thenReturn(authorization.getId());
        when(authorizationValues.get("orbit:authorization:auth:" + authorization.getId())).thenReturn(authorization);

        OAuth2Authorization found = authorizationService.findByToken(
                "state-value", OAuth2TokenType.ACCESS_TOKEN);

        assertThat(found).isNull();
        verify(indexRedisTemplate, never()).delete("orbit:authorization:token:state-value");
    }

    @Test
    void cleansIndexWhenAuthorizationNoLongerExists() {
        when(indexValues.get("orbit:authorization:token:expired-token")).thenReturn("expired-authorization");
        when(authorizationValues.get("orbit:authorization:auth:expired-authorization")).thenReturn(null);

        assertThat(authorizationService.findByToken("expired-token", null)).isNull();
        verify(indexRedisTemplate).delete("orbit:authorization:token:expired-token");
    }

    @Test
    void removesAuthorizationAndItsIndexes() {
        OAuth2Authorization authorization = completeAuthorization(principal(), STATE);
        when(authorizationValues.get("orbit:authorization:auth:" + authorization.getId())).thenReturn(authorization);

        authorizationService.remove(authorization);

        verify(redisTemplate).delete("orbit:authorization:auth:" + authorization.getId());
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Collection<String>> keys = ArgumentCaptor.forClass(Collection.class);
        verify(indexRedisTemplate).delete(keys.capture());
        assertThat(keys.getValue())
                .contains("orbit:authorization:token:access-token", "orbit:authorization:token:" + STATE);
        verify(indexSets).remove("orbit:authorization:principal:" + USER_ID + ":WEB", authorization.getId());
        verify(indexSets).remove("orbit:authorization:session:" + SESSION_TOKEN, authorization.getId());
    }

    @Test
    void removesAllAuthorizationsOfLoginSession() {
        OAuth2Authorization first = completeAuthorization(principal(), STATE);
        OAuth2Authorization second = completeAuthorization(principal(), "other-state");
        when(indexSets.members("orbit:authorization:session:" + SESSION_TOKEN))
                .thenReturn(Set.of(first.getId(), second.getId()));
        when(authorizationValues.get("orbit:authorization:auth:" + first.getId())).thenReturn(first);
        when(authorizationValues.get("orbit:authorization:auth:" + second.getId())).thenReturn(second);

        authorizationService.removeBySessionToken(SESSION_TOKEN);

        verify(redisTemplate).delete("orbit:authorization:auth:" + first.getId());
        verify(redisTemplate).delete("orbit:authorization:auth:" + second.getId());
        verify(indexRedisTemplate).delete("orbit:authorization:session:" + SESSION_TOKEN);
    }

    @Test
    void findsAuthorizationsByPrincipalAndPlatformThroughIndex() {
        OAuth2Authorization authorization = completeAuthorization(principal(), STATE);
        when(indexSets.members("orbit:authorization:principal:" + USER_ID + ":WEB"))
                .thenReturn(Set.of(authorization.getId()));
        when(authorizationValues.get("orbit:authorization:auth:" + authorization.getId())).thenReturn(authorization);

        List<OAuth2Authorization> found = authorizationService.findByPrincipalNameAndPlatform(
                USER_ID, ClientPlatform.WEB);

        assertThat(found).singleElement().isSameAs(authorization);
        verify(redisTemplate, never()).keys(anyString());
    }

    private static UsernamePasswordAuthenticationToken principal() {
        return principal(List.of());
    }

    private static UsernamePasswordAuthenticationToken principal(List<GrantedAuthority> authorities) {
        UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken(
                USER_ID,
                null,
                Map.of(PARAMETER_NAME_PLATFORM, ClientPlatform.WEB.name()),
                authorities
        );
        principal.setDetails(SESSION_TOKEN);
        return principal;
    }

    private static OAuth2Authorization authorization(UsernamePasswordAuthenticationToken principal, String state) {
        RegisteredClient registeredClient = mock(RegisteredClient.class);
        lenient().when(registeredClient.getId()).thenReturn("client-1");
        return OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(principal.getName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(Principal.class.getName(), principal)
                .attribute(OAuth2ParameterNames.STATE, state)
                .build();
    }

    private static OAuth2Authorization enrichedAuthorization(UsernamePasswordAuthenticationToken principal,
                                                              String state) {
        return OAuth2Authorization.from(authorization(principal, state))
                .attribute(PARAMETER_NAME_PLATFORM, ClientPlatform.WEB.name())
                .attribute(PARAMETER_NAME_LOGIN_SESSION_TOKEN, SESSION_TOKEN)
                .build();
    }

    private static OAuth2Authorization rawCompleteAuthorization(UsernamePasswordAuthenticationToken principal,
                                                                 String state) {
        return OAuth2Authorization.from(authorization(principal, state))
                .token(accessToken())
                .build();
    }

    private static OAuth2Authorization completeAuthorization(UsernamePasswordAuthenticationToken principal,
                                                              String state) {
        return OAuth2Authorization.from(enrichedAuthorization(principal, state))
                .token(accessToken())
                .build();
    }

    private static OAuth2AccessToken accessToken() {
        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "access-token",
                Instant.now(),
                Instant.now().plusSeconds(300));
    }
}
