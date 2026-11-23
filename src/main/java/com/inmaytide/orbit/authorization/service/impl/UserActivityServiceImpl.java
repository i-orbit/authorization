package com.inmaytide.orbit.authorization.service.impl;

import com.inmaytide.orbit.authorization.domain.UserActivity;
import com.inmaytide.orbit.authorization.repository.UserRepository;
import com.inmaytide.orbit.authorization.service.UserActivityService;
import com.inmaytide.orbit.framework.core.enums.ClientPlatform;
import com.inmaytide.orbit.framework.core.utils.HttpUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * @author inmaytide
 * @since 2024/12/6
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserActivityServiceImpl implements UserActivityService {

    private static final String CACHE_KEY_PREFIX = "USER_ACTIVITY:";

    /**
     * Activity is kept for 30 minutes after the last request.
     */
    private static final Duration ACTIVITY_TTL = Duration.ofMinutes(30);

    private final ObjectMapper objectMapper;

    private final UserRepository userRepository;

    private final StringRedisTemplate cache;

    @Override
    public void cacheUserActivity(HttpServletRequest request, OAuth2TokenIntrospection tokenClaims) {
        cacheUserActivity(HttpUtils.getClientIpAddress(request), tokenClaims);
    }

    @Override
    public void cacheUserActivity(String ipAddress, OAuth2TokenIntrospection tokenClaims) {
        String userId = tokenClaims.getUsername();
        String platformName = tokenClaims.getClaimAsString("platform");
        if (StringUtils.isAnyBlank(userId, platformName)) {
            log.warn("Failed to record user activity because token user ID or platform is missing");
            return;
        }

        ClientPlatform platform;
        try {
            platform = ClientPlatform.valueOf(platformName);
        } catch (IllegalArgumentException e) {
            log.warn("Failed to record user activity because platform is unsupported, platform: {}", platformName);
            return;
        }

        String cacheKey = getUserActivityCacheKey(platform, userId);
        try {
            UserActivity activity = getCachedActivity(cacheKey).orElseGet(UserActivity::new);
            activity.setUser(userId);
            activity.setLastActivityTime(Instant.now());
            activity.setIpAddress(ipAddress);
            activity.setPlatform(platform);
            cache.opsForValue().set(cacheKey, objectMapper.writeValueAsString(activity), ACTIVITY_TTL);
        } catch (RuntimeException e) {
            log.error("Failed to record user activity, userId: {}, platform: {}", userId, platform, e);
        }
    }

    @Override
    public Long getNumberOfOnlineUsers(String tenant) {
        if (StringUtils.isBlank(tenant)) {
            return 0L;
        }

        Set<String> keys;
        try {
            keys = cache.keys(CACHE_KEY_PREFIX + "*");
        } catch (RuntimeException e) {
            log.error("Failed to load user activity cache keys", e);
            return 0L;
        }
        if (keys == null || keys.isEmpty()) {
            return 0L;
        }

        List<String> userIds = keys.stream()
                .map(UserActivityServiceImpl::getUserIdFromCacheKey)
                .filter(Objects::nonNull)
                .distinct()
                .toList();
        if (userIds.isEmpty()) {
            return 0L;
        }
        return userRepository.countByIdInAndTenantId(userIds, tenant);
    }

    private Optional<UserActivity> getCachedActivity(String cacheKey) {
        String value = cache.opsForValue().get(cacheKey);
        if (StringUtils.isBlank(value)) {
            return Optional.empty();
        }
        try {
            return Optional.ofNullable(objectMapper.readValue(value, UserActivity.class));
        } catch (RuntimeException e) {
            log.warn("Failed to parse cached user activity, cacheKey: {}", cacheKey, e);
            return Optional.empty();
        }
    }

    private static String getUserIdFromCacheKey(String cacheKey) {
        if (!cacheKey.startsWith(CACHE_KEY_PREFIX)) {
            return null;
        }
        int separator = cacheKey.lastIndexOf(":");
        if (separator < CACHE_KEY_PREFIX.length()) {
            return null;
        }
        String userId = cacheKey.substring(separator + 1);
        return StringUtils.isBlank(userId) ? null : userId;
    }

    private String getUserActivityCacheKey(ClientPlatform platform, String userId) {
        return CACHE_KEY_PREFIX + platform.name() + ":" + userId;
    }

}
