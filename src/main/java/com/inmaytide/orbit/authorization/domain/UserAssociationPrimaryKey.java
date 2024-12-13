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
    private Long user;

    @Column(name = "associated")
    private Long associated;

    @Column(name = "category")
    @Enumerated(EnumType.STRING)
    private UserAssociationCategory category;

    public UserAssociationPrimaryKey() {
    }

    public UserAssociationPrimaryKey(Long user, Long associated, UserAssociationCategory category) {
        this.user = user;
        this.associated = associated;
        this.category = category;
    }

    public Long getUser() {
        return user;
    }

    public void setUser(Long user) {
        this.user = user;
    }

    public Long getAssociated() {
        return associated;
    }

    public void setAssociated(Long associated) {
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
