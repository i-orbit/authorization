package com.inmaytide.orbit.authorization.web.rest;

import com.inmaytide.orbit.authorization.domain.CaptchaChallenge;
import com.inmaytide.orbit.authorization.service.CaptchaService;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 滑块拼图验证码挑战。
 *
 * @author inmaytide
 * @since 2026/11/27
 */
@RestController
public class CaptchaResource {

    private final CaptchaService captchaService;

    public CaptchaResource(CaptchaService captchaService) {
        this.captchaService = captchaService;
    }

    @GetMapping("/captcha")
    public ResponseEntity<CaptchaChallenge> createChallenge() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(captchaService.createChallenge());
    }
}
