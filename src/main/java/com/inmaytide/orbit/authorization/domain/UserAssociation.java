package com.inmaytide.orbit.authorization.domain;

import com.inmaytide.orbit.Version;
import com.inmaytide.orbit.commons.constants.Bool;
import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

import java.io.Serial;
import java.io.Serializable;

/**
 * @author inmaytide
 * @since 2024/2/23
 */
@Entity
@Table(name = "user_association", schema = "uaa")
public class UserAssociation implements Serializable {

    @Serial
    private static final long serialVersionUID = Version.SERIAL_VERSION_UID;

    @EmbeddedId
    private UserAssociationPrimaryKey id;

    @Column(name = "defaulted")
    private Bool defaulted;


    public UserAssociationPrimaryKey getId() {
        return id;
    }

    public void setId(UserAssociationPrimaryKey id) {
        this.id = id;
    }

    public Bool getDefaulted() {
        return defaulted;
    }

    public void setDefaulted(Bool defaulted) {
        this.defaulted = defaulted;
    }

}
