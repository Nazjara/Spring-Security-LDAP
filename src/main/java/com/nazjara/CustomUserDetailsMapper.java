package com.nazjara;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.stereotype.Component;

import java.util.Collection;

@Component
public class CustomUserDetailsMapper extends LdapUserDetailsMapper
{
    @Override
    public User mapUserFromContext(DirContextOperations ctx, String username, Collection<? extends GrantedAuthority> authorities)
    {
        var userDetails = (LdapUserDetails) super.mapUserFromContext(ctx, username, authorities);

        return User.builder()
                .dn(userDetails.getDn())
                .username(userDetails.getUsername())
                .password(userDetails.getPassword())
                .authorities(userDetails.getAuthorities())
                .build();
    }
}
