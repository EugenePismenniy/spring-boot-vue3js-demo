package ua.demo.springbootvue3jsdemo.domain.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

public class CustomUser extends User {

    private final long accessTokenValiditySeconds;

    public CustomUser(String username, String password, Collection<? extends GrantedAuthority> authorities, long accessTokenValiditySeconds) {
        super(username, password, authorities);
        this.accessTokenValiditySeconds = accessTokenValiditySeconds;
    }

    public long getAccessTokenValiditySeconds() {
        return accessTokenValiditySeconds;
    }
}
