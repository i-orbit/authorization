package com.inmaytide.orbit.authorization.configuration;

import com.inmaytide.orbit.commons.configuration.GlobalProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * @author inmaytide
 * @since 2024/12/6
 */
@Component
@ConfigurationProperties(prefix = "application")
public class ApplicationProperties extends GlobalProperties {

    private long restrictedTenantMaximumOnlineUsers = 1;

    private boolean allowUsersToLoginSimultaneously = false;

    private boolean hideActualMessageOfUserLoginFailures = true;

    public long getRestrictedTenantMaximumOnlineUsers() {
        return restrictedTenantMaximumOnlineUsers;
    }

    public void setRestrictedTenantMaximumOnlineUsers(long restrictedTenantMaximumOnlineUsers) {
        this.restrictedTenantMaximumOnlineUsers = restrictedTenantMaximumOnlineUsers;
    }

    public boolean isAllowUsersToLoginSimultaneously() {
        return allowUsersToLoginSimultaneously;
    }

    public void setAllowUsersToLoginSimultaneously(boolean allowUsersToLoginSimultaneously) {
        this.allowUsersToLoginSimultaneously = allowUsersToLoginSimultaneously;
    }

    public boolean isHideActualMessageOfUserLoginFailures() {
        return hideActualMessageOfUserLoginFailures;
    }

    public void setHideActualMessageOfUserLoginFailures(boolean hideActualMessageOfUserLoginFailures) {
        this.hideActualMessageOfUserLoginFailures = hideActualMessageOfUserLoginFailures;
    }
}
