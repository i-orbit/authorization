package com.inmaytide.orbit.authorization.domain;

import com.inmaytide.orbit.Version;
import com.inmaytide.orbit.commons.constants.TenantStatus;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.io.Serial;
import java.io.Serializable;

/**
 * @author inmaytide
 * @since 2024/12/6
 */
@Entity
@Table(name = "tenant", schema = "uaa")
public class Tenant implements Serializable {

    @Serial
    private static final long serialVersionUID = Version.SERIAL_VERSION_UID;

    @Id
    private String id;

    private String name;

    private TenantStatus status;

    public void setId(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public TenantStatus getStatus() {
        return status;
    }

    public void setStatus(TenantStatus status) {
        this.status = status;
    }
}
