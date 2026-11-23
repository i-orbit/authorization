package com.inmaytide.orbit.authorization.service.impl;

import com.inmaytide.orbit.authorization.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import tools.jackson.databind.json.JsonMapper;

import java.time.Duration;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserActivityServiceImplTests {

    @Mock
    private UserRepository userRepository;

    @Mock
    private StringRedisTemplate cache;

    @Mock
    private ValueOperations<String, String> valueOperations;

    private UserActivityServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new UserActivityServiceImpl(JsonMapper.builder().build(), userRepository, cache);
    }

    @Test
    void cachesLastActivityWithPlatformAndSourceIp() {
        when(cache.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("USER_ACTIVITY:WEB:user-1")).thenReturn(null);
        OAuth2TokenIntrospection claims = claims("user-1", "WEB");

        service.cacheUserActivity("192.168.1.11", claims);

        ArgumentCaptor<String> activity = ArgumentCaptor.forClass(String.class);
        verify(valueOperations).set(
                eq("USER_ACTIVITY:WEB:user-1"),
                activity.capture(),
                eq(Duration.ofMinutes(30))
        );
        assertThat(activity.getValue())
                .contains("\"user\":\"user-1\"")
                .contains("\"ipAddress\":\"192.168.1.11\"");
    }

    @Test
    void countsDistinctUsersInTheGivenTenant() {
        when(cache.keys("USER_ACTIVITY:*")).thenReturn(Set.of(
                "USER_ACTIVITY:WEB:user-1",
                "USER_ACTIVITY:IOS:user-1",
                "USER_ACTIVITY:ANDROID:user-2",
                "invalid-key"
        ));
        when(userRepository.countByIdInAndTenantId(org.mockito.ArgumentMatchers.anyList(), eq("tenant-1")))
                .thenReturn(2L);

        Long result = service.getNumberOfOnlineUsers("tenant-1");

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<String>> ids = ArgumentCaptor.forClass(List.class);
        verify(userRepository).countByIdInAndTenantId(ids.capture(), eq("tenant-1"));
        assertThat(result).isEqualTo(2L);
        assertThat(ids.getValue()).containsExactlyInAnyOrder("user-1", "user-2");
    }

    private static OAuth2TokenIntrospection claims(String username, String platform) {
        return OAuth2TokenIntrospection.builder()
                .active(true)
                .username(username)
                .claim("platform", platform)
                .build();
    }

}
