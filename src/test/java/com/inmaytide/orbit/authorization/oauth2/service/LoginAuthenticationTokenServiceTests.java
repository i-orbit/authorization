package com.inmaytide.orbit.authorization.oauth2.service;

import com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.core.Authentication;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class LoginAuthenticationTokenServiceTests {

    private static final Duration VALIDITY = Duration.ofMinutes(5);

    private RedisTemplate<String, Authentication> redisTemplate;

    private ValueOperations<String, Authentication> values;

    private LoginAuthenticationTokenService tokenService;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        redisTemplate = mock(RedisTemplate.class);
        values = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(values);
        tokenService = new LoginAuthenticationTokenService(redisTemplate, VALIDITY);
    }

    @Test
    void storesAuthenticationWithConfiguredExpiration() {
        Authentication authentication = authentication();

        String token = tokenService.store(authentication);

        ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
        verify(values).set(key.capture(), same(authentication), eq(VALIDITY));
        assertThat(token).isNotBlank();
        assertThat(key.getValue())
                .isEqualTo("orbit:authentication:" + token);
    }

    @Test
    void findsAuthenticationByToken() {
        Authentication authentication = authentication();
        when(values.get("orbit:authentication:login-token")).thenReturn(authentication);

        assertThat(tokenService.find("login-token")).isSameAs(authentication);
    }

    private static Authentication authentication() {
        return new UsernamePasswordAuthenticationToken(
                "user-1", "credentials", Map.of("platform", "WEB"), List.of());
    }
}
