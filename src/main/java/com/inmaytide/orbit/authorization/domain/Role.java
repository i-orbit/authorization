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
@Table(name = "role", schema = "uaa")
public class Role implements Serializable {

    @Serial
    private static final long serialVersionUID = Version.SERIAL_VERSION_UID;

    @Id
    private Long id;

    private String code;

    private String name;

    public Role() {
    }

    public Role(String code, String name) {
        this.code = code;
        this.name = name;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
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
