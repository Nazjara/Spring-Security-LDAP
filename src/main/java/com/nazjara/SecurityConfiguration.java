package com.nazjara;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.DefaultTlsDirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.security.ldap.ppolicy.PasswordPolicyAwareContextSource;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final CustomUserDetailsMapper customUserDetailsMapper;

    @Bean
    public LdapAuthenticationProvider ldapAuthenticationProvider() {
        var ldapAuthenticationProvider = new LdapAuthenticationProvider(ldapAuthenticator(), ldapAuthoritiesPopulator());
        ldapAuthenticationProvider.setUserDetailsContextMapper(customUserDetailsMapper);
        return ldapAuthenticationProvider;
    }

    @Bean
    public LdapAuthoritiesPopulator ldapAuthoritiesPopulator() {
        var populator = new DefaultLdapAuthoritiesPopulator(ldapContextSource(), "dc=nazjara,dc=com");
        populator.setGroupSearchFilter("(|(&(objectClass=posixGroup)(memberUid={1}))(&(objectClass=group)(member={0})))");
        populator.setRolePrefix("");
        populator.setSearchSubtree(true);
        populator.setIgnorePartialResultException(true);
        populator.setConvertToUpperCase(false);
        return populator;
    }

    @Bean
    public LdapContextSource ldapContextSource() {
        var contextSource = new PasswordPolicyAwareContextSource("ldap://host:9090");
        contextSource.setAuthenticationStrategy(new DefaultTlsDirContextAuthenticationStrategy());
        contextSource.setUserDn("uid=admin,ou=system");
        contextSource.setPassword("password");
        // is needed for tls shutdown on logout operation
        contextSource.setPooled(false);
        return contextSource;
    }

    @Bean
    public LdapAuthenticator ldapAuthenticator() {
        BindAuthenticator authenticator = new BindAuthenticator(ldapContextSource());
        var userSearch = new FilterBasedLdapUserSearch("dc=nazjara,dc=com",
                "(|(uid={0})(sAMAccountName={0})(userPrincipalName={0}))", ldapContextSource());
        authenticator.setUserSearch(userSearch);
        return authenticator;
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(ldapAuthenticationProvider());
    }
}
