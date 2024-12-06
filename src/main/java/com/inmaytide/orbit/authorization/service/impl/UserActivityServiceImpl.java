package com.inmaytide.orbit.authorization.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.inmaytide.orbit.authorization.repository.UserRepository;
import com.inmaytide.orbit.authorization.service.UserActivityService;
import com.inmaytide.orbit.commons.constants.Platforms;
import com.inmaytide.orbit.commons.domain.UserActivity;
import com.inmaytide.orbit.commons.utils.ValueCaches;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

import static com.inmaytide.orbit.commons.constants.Constants.CacheNames.USER_ACTIVITY;
import static com.inmaytide.orbit.commons.utils.HttpUtils.getClientIpAddress;

/**
 * @author inmaytide
 * @since 2024/12/6
 */
@Service
public class UserActivityServiceImpl implements UserActivityService {

    private final static Logger log = LoggerFactory.getLogger(UserActivityServiceImpl.class);

    private final ObjectMapper objectMapper;

    private final UserRepository userRepository;

    public UserActivityServiceImpl(ObjectMapper objectMapper, UserRepository userRepository) {
        this.objectMapper = objectMapper;
        this.userRepository = userRepository;
    }

    @Override
    public void cacheUserActivity(HttpServletRequest request, OAuth2TokenIntrospection tokenClaims) {
        try {
            Platforms platform = Platforms.valueOf(tokenClaims.getClaimAsString("platform"));
            Long userId = NumberUtils.createLong(tokenClaims.getUsername());
            try {
                UserActivity activity = ValueCaches
                        .getFor(USER_ACTIVITY, getUserActivityCacheKey(platform, userId), UserActivity.class)
                        .orElseGet(UserActivity::new);
                activity.setUser(userId);
                activity.setLastActivityTime(Instant.now());
                activity.setIpAddress(getClientIpAddress(request));
                activity.setPlatform(platform);
                ValueCaches.put(USER_ACTIVITY, getUserActivityCacheKey(platform, userId), objectMapper.writeValueAsString(activity));
            } catch (Exception e) {
                log.error("Failed to record User{id = {}, platform = {}} activity, Cause by: ", userId, platform.name(), e);
            }
        } catch (Exception e) {
            log.error("Failed to retrieve user ID and platform from authentication, Cause by: ", e);
        }
    }

    @Override
    public Long getNumberOfOnlineUsers(Long tenant) {
        List<Long> all = ValueCaches.keys(USER_ACTIVITY).stream()
                .map(e -> StringUtils.split(e, "::")[1])
                .map(NumberUtils::createLong)
                .toList();
        if (all.isEmpty()) {
            return 0L;
        }
        return userRepository.count((root, query, cb) -> cb.and(root.get("id").in(all), cb.equal(root.get("tenant"), tenant)));
    }

    private String getUserActivityCacheKey(Platforms platform, Long userId) {
        return platform.name() + "::" + userId;
    }
}
