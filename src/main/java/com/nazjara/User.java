package com.nazjara;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.userdetails.LdapUserDetails;

import java.util.Collection;
import java.util.Objects;

@AllArgsConstructor
@Getter
@Setter
@Builder
public class User implements LdapUserDetails {
    private String dn;
    private String username;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String getDn() {
        return dn;
    }

    @Override
    public void eraseCredentials() {
        password = null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        User user = (User) o;
        return dn.equals(user.dn);
    }

    @Override
    public int hashCode() {
        return Objects.hash(dn);
    }
}
