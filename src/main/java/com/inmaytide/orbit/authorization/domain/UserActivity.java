package com.inmaytide.orbit.authorization.domain;

import com.inmaytide.orbit.framework.core.enums.ClientPlatform;
import lombok.Data;

import java.time.Instant;

/**
 * Last known activity of a user on a client platform.
 *
 * @author inmaytide
 * @since 2026/11/23
 */
@Data
public class UserActivity {

    private String user;

    private String ipAddress;

    private ClientPlatform platform;

    private Instant onlineTime = Instant.now();

    private Instant lastActivityTime;

    private Instant offlineTime;

}
