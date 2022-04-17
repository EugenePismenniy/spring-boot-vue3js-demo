package ua.demo.springbootvue3jsdemo.security.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import ua.demo.springbootvue3jsdemo.domain.user.CustomUser;

import java.util.Date;
import java.util.List;

import static java.lang.System.currentTimeMillis;
import static java.util.stream.Collectors.toList;

@Service
public class JwtHmac256Helper {

    public static final long DEFAULT_ACCESS_TOKEN_VALIDITY_SECONDS = 8 * 60 * 60;

    private final Algorithm algorithm;

    public JwtHmac256Helper(@Value("${jwt.secret}") String secret) {
       this.algorithm = Algorithm.HMAC256(secret);
    }


    public String createToken(UserDetails userDetails) {
        return JWT.create()
                .withSubject(userDetails.getUsername())
                .withClaim("roles", authoritiesAsStringList(userDetails))
                .withExpiresAt(new Date(currentTimeMillis() + accessTokenValiditySeconds(userDetails) * 1000))
                .sign(this.algorithm);
    }

    private long accessTokenValiditySeconds(UserDetails userDetails) {
        if (userDetails instanceof CustomUser) {
            return ((CustomUser) userDetails).getAccessTokenValiditySeconds();
        }
        return DEFAULT_ACCESS_TOKEN_VALIDITY_SECONDS;
    }

    private List<String> authoritiesAsStringList(UserDetails userDetails) {
        return userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(toList());
    }
}
