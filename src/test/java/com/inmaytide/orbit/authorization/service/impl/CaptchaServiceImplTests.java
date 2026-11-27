package com.inmaytide.orbit.authorization.service.impl;

import com.inmaytide.orbit.authorization.domain.CaptchaChallenge;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CaptchaServiceImplTests {

    private static final String CAPTCHA_KEY_PREFIX = "orbit:captcha:";

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> values;

    private CaptchaServiceImpl captchaService;

    @BeforeEach
    void setUp() {
        when(redisTemplate.opsForValue()).thenReturn(values);
        captchaService = new CaptchaServiceImpl(redisTemplate);
    }

    @Test
    void createsChallengeWithImagesAndStoresTargetPosition() {
        CaptchaChallenge challenge = captchaService.createChallenge();

        assertThat(challenge.getId()).isNotBlank();
        assertThat(challenge.getBackground()).startsWith("data:image/png;base64,");
        assertThat(challenge.getPiece()).startsWith("data:image/png;base64,");
        assertThat(challenge.getWidth()).isGreaterThan(challenge.getPieceWidth());
        assertThat(challenge.getTolerance()).isPositive();
        assertThat(challenge.getExpiresIn()).isPositive();

        ArgumentCaptor<String> target = ArgumentCaptor.forClass(String.class);
        verify(values).set(startsWith(CAPTCHA_KEY_PREFIX), target.capture(), eq(Duration.ofMinutes(2)));
        assertThat(Integer.parseInt(target.getValue())).isBetween(0, challenge.getWidth() - challenge.getPieceWidth());
    }

    @Test
    void acceptsPositionWithinToleranceAndConsumesChallenge() {
        String key = CAPTCHA_KEY_PREFIX + "captcha-id";
        when(values.get(key)).thenReturn("100");

        assertThat(captchaService.verify("captcha-id", 105)).isTrue();
        verify(redisTemplate).delete(key);
    }

    @Test
    void rejectsPositionOutsideToleranceAndConsumesChallenge() {
        String key = CAPTCHA_KEY_PREFIX + "captcha-id";
        when(values.get(key)).thenReturn("100");

        assertThat(captchaService.verify("captcha-id", 120)).isFalse();
        verify(redisTemplate).delete(key);
    }

    @Test
    void rejectsMissingOrExpiredChallenge() {
        when(values.get(anyString())).thenReturn(null);

        assertThat(captchaService.verify(null, 100)).isFalse();
        assertThat(captchaService.verify("", 100)).isFalse();
        assertThat(captchaService.verify("expired-id", 100)).isFalse();
    }
}
