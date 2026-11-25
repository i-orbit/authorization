package com.inmaytide.orbit.authorization.domain;

import com.inmaytide.orbit.framework.Version;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;

/**
 * @author inmaytide
 * @since 2026/11/25
 */
@Data
@Entity
@Table(name = "t_tenant", schema = "iam")
public class Tenant implements Serializable {

    @Serial
    private static final long serialVersionUID = Version.SERIAL_VERSION_UID;

    @Id
    private String id;

    private String code;

    private String name;

    private Integer status;

    private String deploymentMode;

    private String edition;

    private String modules;

    private Instant expiredAt;

    private Integer maxUsers;

    private Integer maxOnlineUsers;

    private Integer deleted = 0;

}
