package com.inmaytide.orbit.authorization.oauth2.service;

import com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken;
import com.inmaytide.orbit.framework.core.enums.ClientPlatform;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.security.Principal;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken.PARAMETER_NAME_PLATFORM;

/**
 * 基于 Redis 的 OAuth2 授权服务实现。<br/>
 * 负责 OAuth2Authorization 的持久化、查询和删除，用于存储授权码、Access Token 及其关联的授权信息。<br/>
 * 支持通过授权 ID、Token 值及 Token 类型检索授权信息，并利用 Redis 实现授权信息的集中存储与过期管理。<br/>
 *
 * @author inmaytide
 * @since 2023/04/29
 */
@Component
public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private static final String REDIS_KEY_PREFIX = "orbit:authorization:";

    private static final long TTL_AUTHORIZATION = 30 * 60 * 1000;

    private static final Set<String> LOGIN_AUTHORIZATION_ATTRIBUTES = Set.of(PARAMETER_NAME_PLATFORM);

    private final Map<String, OAuth2Authorization> initializedAuthorizations = new ConcurrentHashMap<>();

    private final RedisTemplate<String, OAuth2Authorization> redisTemplate;

    public RedisOAuth2AuthorizationService(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, OAuth2Authorization> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        template.setKeySerializer(StringRedisSerializer.UTF_8);
        template.setValueSerializer(new JdkSerializationRedisSerializer());
        template.afterPropertiesSet();
        this.redisTemplate = template;
    }

    private String buildCacheKey(String authorizationId) {
        return REDIS_KEY_PREFIX + authorizationId;
    }

    private String buildCacheKey(OAuth2Authorization authorization) {
        return buildCacheKey(authorization.getId());
    }

    @Override
    public void save(@Nonnull OAuth2Authorization authorization) {
        Assert.notNull(authorization, "Authorization cannot be null");
        OAuth2Authorization enriched = copyLoginAttributes(authorization);
        if (isComplete(enriched)) {
            redisTemplate.opsForValue().set(buildCacheKey(enriched), enriched, Duration.ofMillis(TTL_AUTHORIZATION));
        } else {
            this.initializedAuthorizations.put(enriched.getId(), enriched);
        }
    }

    @Override
    public void remove(@Nonnull OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        if (isComplete(authorization)) {
            redisTemplate.opsForValue().getAndDelete(buildCacheKey(authorization));
        } else {
            this.initializedAuthorizations.remove(authorization.getId());
        }
    }

    @Override
    public OAuth2Authorization findById(@Nonnull String id) {
        Assert.hasText(id, "id cannot be empty");
        return redisTemplate.opsForValue().get(buildCacheKey(id));
    }

    @Override
    public OAuth2Authorization findByToken(@Nonnull String token, @Nullable OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        return Stream.concat(findAll().stream(), initializedAuthorizations.values().stream())
                .filter(authorization -> hasToken(authorization, token, tokenType))
                .findFirst()
                .orElse(null);
    }

    private List<OAuth2Authorization> findAll() {
        Set<String> keys = redisTemplate.keys(REDIS_KEY_PREFIX + "*");
        if (keys == null || keys.isEmpty()) {
            return Collections.emptyList();
        }
        List<OAuth2Authorization> authorizations = redisTemplate.opsForValue().multiGet(keys);
        if (authorizations == null) {
            return Collections.emptyList();
        }
        return authorizations.stream()
                .filter(Objects::nonNull)
                .toList();
    }

    public List<OAuth2Authorization> findByPrincipalNameAndPlatform(@Nonnull String principalName,
                                                                    @Nonnull ClientPlatform platform) {
        Assert.hasText(principalName, "principalName cannot be empty");
        Assert.notNull(platform, "platform cannot be null");
        return Stream.concat(findAll().stream(), initializedAuthorizations.values().stream())
                .filter(authorization -> matchesPrincipalNameAndPlatform(authorization, principalName, platform))
                .collect(Collectors.toList());
    }

    private static boolean matchesPrincipalNameAndPlatform(OAuth2Authorization authorization,
                                                            String principalName,
                                                            ClientPlatform platform) {
        if (!Objects.equals(principalName, authorization.getPrincipalName())) {
            return false;
        }
        Object value = authorization.getAttribute(PARAMETER_NAME_PLATFORM);
        return value != null && platform.name().equals(value.toString());
    }

    private static OAuth2Authorization copyLoginAttributes(OAuth2Authorization authorization) {
        if (authorization.getAttribute(PARAMETER_NAME_PLATFORM) != null) {
            return authorization;
        }

        Object principal = authorization.getAttribute(Principal.class.getName());
        if (!(principal instanceof UsernamePasswordAuthenticationToken token)) {
            return authorization;
        }

        Map<String, Object> parameters = token.getAdditionalParameters();
        if (parameters == null || parameters.isEmpty()) {
            return authorization;
        }

        return OAuth2Authorization.from(authorization)
                .attributes(attributes -> {
                    for (String name : LOGIN_AUTHORIZATION_ATTRIBUTES) {
                        Object value = parameters.get(name);
                        if (value != null) {
                            attributes.putIfAbsent(name, value);
                        }
                    }
                })
                .build();
    }

    private static boolean isComplete(OAuth2Authorization authorization) {
        return authorization.getAccessToken() != null;
    }

    private static boolean hasToken(OAuth2Authorization authorization, String token, @Nullable OAuth2TokenType tokenType) {
        if (tokenType == null) {
            return matchesState(authorization, token) || matchesAuthorizationCode(authorization, token) || matchesAccessToken(authorization, token) || matchesRefreshToken(authorization, token);
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            return matchesState(authorization, token);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            return matchesAuthorizationCode(authorization, token);
        } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            return matchesAccessToken(authorization, token);
        } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            return matchesRefreshToken(authorization, token);
        }
        return false;
    }

    private static boolean matchesState(OAuth2Authorization authorization, String token) {
        return token.equals(authorization.getAttribute(OAuth2ParameterNames.STATE));
    }

    private static boolean matchesAuthorizationCode(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authorization.getToken(OAuth2AuthorizationCode.class);
        return authorizationCode != null && authorizationCode.getToken().getTokenValue().equals(token);
    }

    private static boolean matchesAccessToken(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getToken(OAuth2AccessToken.class);
        return accessToken != null && accessToken.getToken().getTokenValue().equals(token);
    }

    private static boolean matchesRefreshToken(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getToken(OAuth2RefreshToken.class);
        return refreshToken != null && refreshToken.getToken().getTokenValue().equals(token);
    }

}
