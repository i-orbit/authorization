package com.inmaytide.orbit.authorization.domain;

import com.inmaytide.orbit.Version;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.io.Serial;
import java.io.Serializable;

/**
 * @author inmaytide
 * @since 2024/5/30
 */
@Entity
@Table(name = "position", schema = "uaa")
public class Position implements Serializable {

    @Serial
    private static final long serialVersionUID = Version.SERIAL_VERSION_UID;

    @Id
    private String id;

    private String code;

    private String name;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

}
