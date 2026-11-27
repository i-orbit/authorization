package com.inmaytide.orbit.authorization.service;

import com.inmaytide.orbit.authorization.domain.CaptchaChallenge;

/**
 * 滑块拼图验证码。
 *
 * @author inmaytide
 * @since 2026/11/27
 */
public interface CaptchaService {

    CaptchaChallenge createChallenge();

    /**
     * 校验滑块位置。挑战为一次性使用，无论成功失败都会失效。
     */
    boolean verify(String id, Integer x);
}
