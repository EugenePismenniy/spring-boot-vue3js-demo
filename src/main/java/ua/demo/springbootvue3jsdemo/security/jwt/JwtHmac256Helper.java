package ua.demo.springbootvue3jsdemo.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import ua.demo.springbootvue3jsdemo.domain.user.CustomUser;

import java.util.Date;
import java.util.List;

import static java.lang.System.currentTimeMillis;
import static java.util.stream.Collectors.toList;

@Service
public class JwtHmac256Helper {

    private static final String ROLES_CLAIM = "roles";

    private static final long DEFAULT_ACCESS_TOKEN_VALIDITY_SECONDS = 8 * 60 * 60;

    private final Algorithm algorithm;
    private final JWTVerifier jwtVerifier;

    public JwtHmac256Helper(@Value("${jwt.secret}") String secret) {
        final Algorithm hmac256Alg = Algorithm.HMAC256(secret);
        this.algorithm = hmac256Alg;
        this.jwtVerifier = JWT.require(hmac256Alg).build();
    }

    public UsernamePasswordAuthenticationToken verifyToken(String jwtToken) {
        try {
            DecodedJWT decodedJWT = this.jwtVerifier.verify(jwtToken);

            String username = decodedJWT.getSubject();

            List<SimpleGrantedAuthority> roles = decodedJWT.getClaim(ROLES_CLAIM).asList(String.class)
                    .stream().map(SimpleGrantedAuthority::new).collect(toList());

            return new UsernamePasswordAuthenticationToken(username, null, roles);

        } catch (Exception e) {
            throw new JwtAuthenticationException("Fail token verification", e);
        }
    }

    public String createToken(UserDetails userDetails) {
        return JWT.create()
                .withSubject(userDetails.getUsername())
                .withClaim(ROLES_CLAIM, authoritiesAsStringList(userDetails))
                .withExpiresAt(tokenDateExpires(userDetails))
                .sign(this.algorithm);
    }

    private Date tokenDateExpires(UserDetails userDetails) {
        long accessTokenValiditySeconds = DEFAULT_ACCESS_TOKEN_VALIDITY_SECONDS;
        if (userDetails instanceof CustomUser) {
            accessTokenValiditySeconds =  ((CustomUser) userDetails).getAccessTokenValiditySeconds();
        }
        return new Date(currentTimeMillis() + accessTokenValiditySeconds * 1000);
    }

    private List<String> authoritiesAsStringList(UserDetails userDetails) {
        return userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(toList());
    }
}
