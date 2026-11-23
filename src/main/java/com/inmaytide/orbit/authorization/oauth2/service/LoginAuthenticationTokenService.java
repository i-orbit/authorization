package com.inmaytide.orbit.authorization.oauth2.service;

import com.inmaytide.orbit.framework.security.SecurityProperties;
import jakarta.annotation.Nonnull;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.time.Duration;
import java.util.Base64;

/**
 * Stores short-lived login authentication state used by the OAuth2 authorization endpoint.
 *
 * @author inmaytide
 * @since 2026/11/20
 */
@Component
public class LoginAuthenticationTokenService {

    private static final String REDIS_KEY_PREFIX = "orbit:authentication:";

    private static final StringKeyGenerator TOKEN_GENERATOR =
            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 32);

    private final RedisTemplate<String, Authentication> redisTemplate;

    private final Duration validity;

    @Autowired
    public LoginAuthenticationTokenService(RedisConnectionFactory connectionFactory, SecurityProperties properties) {
        this(createRedisTemplate(connectionFactory), Duration.ofSeconds(
                Math.max(1, properties.getUserClient().getAccessTokenValiditySeconds())));
    }

    LoginAuthenticationTokenService(RedisTemplate<String, Authentication> redisTemplate, Duration validity) {
        this.redisTemplate = redisTemplate;
        this.validity = validity;
    }

    public String store(@Nonnull Authentication authentication) {
        Assert.notNull(authentication, "authentication cannot be null");
        String token = TOKEN_GENERATOR.generateKey();
        redisTemplate.opsForValue().set(buildCacheKey(token), authentication, validity);
        return token;
    }

    public @Nullable Authentication find(@Nonnull String token) {
        Assert.hasText(token, "token cannot be empty");
        return redisTemplate.opsForValue().get(buildCacheKey(token));
    }

    private static String buildCacheKey(String token) {
        return REDIS_KEY_PREFIX + token;
    }

    private static RedisTemplate<String, Authentication> createRedisTemplate(
            RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, Authentication> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        template.setKeySerializer(StringRedisSerializer.UTF_8);
        template.setValueSerializer(new JdkSerializationRedisSerializer());
        template.afterPropertiesSet();
        return template;
    }
}
