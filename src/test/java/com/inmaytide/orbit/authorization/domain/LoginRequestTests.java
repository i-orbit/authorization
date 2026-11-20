package com.inmaytide.orbit.authorization.domain;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

class LoginRequestTests {

    @Test
    void parsesForceReplacementAliasesFromJson() {
        JsonMapper mapper = JsonMapper.builder().build();

        LoginRequest legacyJson = mapper.readValue("""
                {
                  "username": "alice",
                  "password": "secret",
                  "platform": "WEB",
                  "forcedReplacement": 1
                }
                """, LoginRequest.class);
        LoginRequest typoJson = mapper.readValue("""
                {
                  "username": "alice",
                  "password": "secret",
                  "platform": "WEB",
                  "forceReplacemnt": true
                }
                """, LoginRequest.class);

        assertThat(legacyJson.isForceReplacement()).isTrue();
        assertThat(typoJson.isForceReplacement()).isTrue();
    }
}
