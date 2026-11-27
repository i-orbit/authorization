package com.inmaytide.orbit.authorization.oauth2.service;

import com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken;
import com.inmaytide.orbit.framework.core.enums.ClientPlatform;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
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
import org.springframework.util.StringUtils;

import java.security.Principal;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken.PARAMETER_NAME_LOGIN_SESSION_TOKEN;
import static com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken.PARAMETER_NAME_PLATFORM;
import static com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken.PARAMETER_NAME_TENANT_ID;

/**
 * 基于 Redis 的 OAuth2 授权服务实现。<br/>
 * 负责 OAuth2Authorization 的持久化、查询和删除，用于存储授权码、Access Token 及其关联的授权信息。<br/>
 * 使用 token / principal / login-session 索引替代 Redis KEYS 扫描，并让未完成的授权也落在 Redis，
 * 以支持授权服务器多实例部署。
 *
 * @author inmaytide
 * @since 2023/04/29
 */
@Component
public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private static final String AUTHORIZATION_KEY_PREFIX = "orbit:authorization:auth:";

    private static final String TOKEN_KEY_PREFIX = "orbit:authorization:token:";

    private static final String PRINCIPAL_KEY_PREFIX = "orbit:authorization:principal:";

    private static final String SESSION_KEY_PREFIX = "orbit:authorization:session:";

    /**
     * 尚未换取 access_token 的授权（授权码阶段）只需保留到 code 过期之后。
     */
    private static final Duration INITIALIZED_AUTHORIZATION_TTL = Duration.ofMinutes(10);

    private static final Duration DEFAULT_AUTHORIZATION_TTL = Duration.ofMinutes(30);

    private static final Set<String> LOGIN_AUTHORIZATION_ATTRIBUTES = Set.of(
            PARAMETER_NAME_PLATFORM, PARAMETER_NAME_TENANT_ID, PARAMETER_NAME_LOGIN_SESSION_TOKEN);

    private final RedisTemplate<String, OAuth2Authorization> redisTemplate;

    private final StringRedisTemplate indexRedisTemplate;

    private final LoginAuthenticationTokenService loginAuthenticationTokenService;

    @Autowired
    public RedisOAuth2AuthorizationService(RedisConnectionFactory connectionFactory,
                                           LoginAuthenticationTokenService loginAuthenticationTokenService) {
        this(createAuthorizationTemplate(connectionFactory), createIndexTemplate(connectionFactory),
                loginAuthenticationTokenService);
    }

    RedisOAuth2AuthorizationService(RedisTemplate<String, OAuth2Authorization> redisTemplate,
                                    StringRedisTemplate indexRedisTemplate,
                                    LoginAuthenticationTokenService loginAuthenticationTokenService) {
        this.redisTemplate = redisTemplate;
        this.indexRedisTemplate = indexRedisTemplate;
        this.loginAuthenticationTokenService = loginAuthenticationTokenService;
    }

    @Override
    public void save(@Nonnull OAuth2Authorization authorization) {
        Assert.notNull(authorization, "Authorization cannot be null");
        OAuth2Authorization enriched = copyLoginAttributes(authorization);
        Duration ttl = isComplete(enriched) ? authorizationTtl() : INITIALIZED_AUTHORIZATION_TTL;

        redisTemplate.opsForValue().set(authorizationKey(enriched.getId()), enriched, ttl);
        indexTokens(enriched, ttl);
        indexPrincipalAndPlatform(enriched, ttl);
        indexLoginSession(enriched, ttl);
    }

    @Override
    public void remove(@Nonnull OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        OAuth2Authorization target = findById(authorization.getId());
        if (target == null) {
            target = authorization;
        }
        redisTemplate.delete(authorizationKey(target.getId()));
        removeTokenIndexes(target);
        removePrincipalIndex(target);
        removeLoginSessionIndex(target);
    }

    @Override
    public @Nullable OAuth2Authorization findById(@Nonnull String id) {
        Assert.hasText(id, "id cannot be empty");
        return redisTemplate.opsForValue().get(authorizationKey(id));
    }

    @Override
    public @Nullable OAuth2Authorization findByToken(@Nonnull String token, @Nullable OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        String authorizationId = indexRedisTemplate.opsForValue().get(tokenKey(token));
        if (!StringUtils.hasText(authorizationId)) {
            return null;
        }

        OAuth2Authorization authorization = findById(authorizationId);
        if (authorization == null) {
            // 索引指向已过期的授权，顺手清理
            indexRedisTemplate.delete(tokenKey(token));
            return null;
        }
        if (!hasToken(authorization, token, tokenType)) {
            // 可能是 token_type_hint 不匹配，保留索引供后续不带 hint 的查询使用
            return null;
        }

        // 用户每次 API 请求都会 introspect access_token，借此滑动登录会话的空闲时间
        renewLoginSession(authorization);
        return authorization;
    }

    public List<OAuth2Authorization> findByPrincipalNameAndPlatform(@Nonnull String principalName,
                                                                    @Nonnull ClientPlatform platform) {
        Assert.hasText(principalName, "principalName cannot be empty");
        Assert.notNull(platform, "platform cannot be null");

        Set<String> authorizationIds = indexRedisTemplate.opsForSet()
                .members(principalKey(principalName, platform.name()));
        if (authorizationIds == null || authorizationIds.isEmpty()) {
            return Collections.emptyList();
        }
        return authorizationIds.stream()
                .map(this::findById)
                .filter(Objects::nonNull)
                .filter(authorization -> matchesPrincipalNameAndPlatform(authorization, principalName, platform))
                .collect(Collectors.toList());
    }

    /**
     * 强制替换在线会话时，同时注销该授权关联的登录会话及该会话下的全部授权，
     * 避免旧浏览器静默重新授权。
     */
    public void removeAndInvalidateSession(@Nonnull OAuth2Authorization authorization) {
        Object value = authorization.getAttribute(PARAMETER_NAME_LOGIN_SESSION_TOKEN);
        if (value instanceof String sessionToken && !sessionToken.isBlank()) {
            removeBySessionToken(sessionToken);
            if (loginAuthenticationTokenService != null) {
                loginAuthenticationTokenService.remove(sessionToken);
            }
            return;
        }
        remove(authorization);
    }

    /**
     * 注销登录会话下的全部授权，用于退出登录。
     */
    public void removeBySessionToken(@Nonnull String sessionToken) {
        Assert.hasText(sessionToken, "sessionToken cannot be empty");
        String sessionKey = sessionKey(sessionToken);
        Set<String> authorizationIds = indexRedisTemplate.opsForSet().members(sessionKey);
        if (authorizationIds != null) {
            authorizationIds.stream()
                    .map(this::findById)
                    .filter(Objects::nonNull)
                    .forEach(this::remove);
        }
        indexRedisTemplate.delete(sessionKey);
    }

    private void renewLoginSession(@Nonnull OAuth2Authorization authorization) {
        if (loginAuthenticationTokenService == null) {
            return;
        }
        Object value = authorization.getAttribute(PARAMETER_NAME_LOGIN_SESSION_TOKEN);
        if (value instanceof String sessionToken && !sessionToken.isBlank()) {
            loginAuthenticationTokenService.renew(sessionToken);
            indexRedisTemplate.expire(sessionKey(sessionToken), authorizationTtl());
        }
    }

    private Duration authorizationTtl() {
        if (loginAuthenticationTokenService == null) {
            return DEFAULT_AUTHORIZATION_TTL;
        }
        Duration validity = loginAuthenticationTokenService.getValidity();
        return validity == null ? DEFAULT_AUTHORIZATION_TTL : validity;
    }

    private void indexTokens(OAuth2Authorization authorization, Duration ttl) {
        indexToken(authorization, authorization.getToken(OAuth2AuthorizationCode.class), ttl);
        indexToken(authorization, authorization.getAccessToken(), ttl);
        indexToken(authorization, authorization.getRefreshToken(), ttl);

        Object state = authorization.getAttribute(OAuth2ParameterNames.STATE);
        if (state instanceof String value && !value.isBlank()) {
            indexValue(tokenKey(value), authorization.getId(), ttl);
        }
    }

    private void indexToken(OAuth2Authorization authorization,
                            OAuth2Authorization.Token<?> token,
                            Duration ttl) {
        if (token == null || token.getToken() == null) {
            return;
        }
        String tokenValue = token.getToken().getTokenValue();
        if (StringUtils.hasText(tokenValue)) {
            indexValue(tokenKey(tokenValue), authorization.getId(), ttl);
        }
    }

    private void indexValue(String key, String authorizationId, Duration ttl) {
        indexRedisTemplate.opsForValue().set(key, authorizationId, ttl);
    }

    private void indexPrincipalAndPlatform(OAuth2Authorization authorization, Duration ttl) {
        String principalName = authorization.getPrincipalName();
        Object platform = authorization.getAttribute(PARAMETER_NAME_PLATFORM);
        if (!StringUtils.hasText(principalName) || platform == null) {
            return;
        }
        String key = principalKey(principalName, platform.toString());
        indexRedisTemplate.opsForSet().add(key, authorization.getId());
        indexRedisTemplate.expire(key, ttl);
    }

    private void indexLoginSession(OAuth2Authorization authorization, Duration ttl) {
        Object value = authorization.getAttribute(PARAMETER_NAME_LOGIN_SESSION_TOKEN);
        if (!(value instanceof String sessionToken) || sessionToken.isBlank()) {
            return;
        }
        String key = sessionKey(sessionToken);
        indexRedisTemplate.opsForSet().add(key, authorization.getId());
        indexRedisTemplate.expire(key, ttl);
    }

    private void removeTokenIndexes(OAuth2Authorization authorization) {
        List<String> keys = new ArrayList<>(4);
        addTokenKey(keys, authorization.getToken(OAuth2AuthorizationCode.class));
        addTokenKey(keys, authorization.getAccessToken());
        addTokenKey(keys, authorization.getRefreshToken());

        Object state = authorization.getAttribute(OAuth2ParameterNames.STATE);
        if (state instanceof String value && !value.isBlank()) {
            keys.add(tokenKey(value));
        }
        if (!keys.isEmpty()) {
            indexRedisTemplate.delete(keys);
        }
    }

    private void addTokenKey(List<String> keys, OAuth2Authorization.Token<?> token) {
        if (token == null || token.getToken() == null) {
            return;
        }
        String tokenValue = token.getToken().getTokenValue();
        if (StringUtils.hasText(tokenValue)) {
            keys.add(tokenKey(tokenValue));
        }
    }

    private void removePrincipalIndex(OAuth2Authorization authorization) {
        String principalName = authorization.getPrincipalName();
        Object platform = authorization.getAttribute(PARAMETER_NAME_PLATFORM);
        if (StringUtils.hasText(principalName) && platform != null) {
            indexRedisTemplate.opsForSet().remove(
                    principalKey(principalName, platform.toString()), authorization.getId());
        }
    }

    private void removeLoginSessionIndex(OAuth2Authorization authorization) {
        Object value = authorization.getAttribute(PARAMETER_NAME_LOGIN_SESSION_TOKEN);
        if (value instanceof String sessionToken && !sessionToken.isBlank()) {
            indexRedisTemplate.opsForSet().remove(sessionKey(sessionToken), authorization.getId());
        }
    }

    private String authorizationKey(String authorizationId) {
        return AUTHORIZATION_KEY_PREFIX + authorizationId;
    }

    private String tokenKey(String token) {
        return TOKEN_KEY_PREFIX + token;
    }

    private String principalKey(String principalName, String platform) {
        return PRINCIPAL_KEY_PREFIX + principalName + ":" + platform;
    }

    private String sessionKey(String sessionToken) {
        return SESSION_KEY_PREFIX + sessionToken;
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
        if (LOGIN_AUTHORIZATION_ATTRIBUTES.stream()
                .allMatch(name -> authorization.getAttribute(name) != null)) {
            return authorization;
        }

        Object principal = authorization.getAttribute(Principal.class.getName());
        if (!(principal instanceof UsernamePasswordAuthenticationToken token)) {
            return authorization;
        }

        Map<String, Object> parameters = token.getAdditionalParameters();
        Object loginSessionToken = token.getDetails();
        boolean noLoginParameters = parameters == null || parameters.isEmpty();
        boolean noLoginSessionToken = !(loginSessionToken instanceof String);
        if (noLoginParameters && noLoginSessionToken) {
            return authorization;
        }

        return OAuth2Authorization.from(authorization)
                .attributes(attributes -> {
                    if (parameters != null) {
                        for (String name : LOGIN_AUTHORIZATION_ATTRIBUTES) {
                            Object value = parameters.get(name);
                            if (value != null) {
                                attributes.putIfAbsent(name, value);
                            }
                        }
                    }
                    if (loginSessionToken instanceof String sessionToken && !sessionToken.isBlank()) {
                        attributes.putIfAbsent(PARAMETER_NAME_LOGIN_SESSION_TOKEN, sessionToken);
                    }
                })
                .build();
    }

    private static boolean isComplete(OAuth2Authorization authorization) {
        return authorization.getAccessToken() != null;
    }

    private static boolean hasToken(OAuth2Authorization authorization, String token, @Nullable OAuth2TokenType tokenType) {
        if (tokenType == null) {
            return matchesState(authorization, token) || matchesAuthorizationCode(authorization, token)
                    || matchesAccessToken(authorization, token) || matchesRefreshToken(authorization, token);
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

    private static RedisTemplate<String, OAuth2Authorization> createAuthorizationTemplate(
            RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, OAuth2Authorization> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        template.setKeySerializer(StringRedisSerializer.UTF_8);
        template.setValueSerializer(new JdkSerializationRedisSerializer());
        template.afterPropertiesSet();
        return template;
    }

    private static StringRedisTemplate createIndexTemplate(RedisConnectionFactory connectionFactory) {
        StringRedisTemplate template = new StringRedisTemplate();
        template.setConnectionFactory(connectionFactory);
        template.afterPropertiesSet();
        return template;
    }
}
