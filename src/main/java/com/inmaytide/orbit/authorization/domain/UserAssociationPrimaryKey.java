package com.inmaytide.orbit.authorization.domain;

import com.inmaytide.orbit.commons.constants.UserAssociationCategory;
import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;

import java.util.Objects;

/**
 * @author inmaytide
 * @since 2024/12/12
 */
@Embeddable
public class UserAssociationPrimaryKey {

    @Column(name = "user")
    private String user;

    @Column(name = "associated")
    private String associated;

    @Column(name = "category")
    @Enumerated(EnumType.STRING)
    private UserAssociationCategory category;

    public UserAssociationPrimaryKey() {
    }

    public UserAssociationPrimaryKey(String user, String associated, UserAssociationCategory category) {
        this.user = user;
        this.associated = associated;
        this.category = category;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getAssociated() {
        return associated;
    }

    public void setAssociated(String associated) {
        this.associated = associated;
    }

    public UserAssociationCategory getCategory() {
        return category;
    }

    public void setCategory(UserAssociationCategory category) {
        this.category = category;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        UserAssociationPrimaryKey that = (UserAssociationPrimaryKey) o;
        return Objects.equals(user, that.user) && Objects.equals(associated, that.associated) && category == that.category;
    }

    @Override
    public int hashCode() {
        return Objects.hash(user, associated, category);
    }
}
