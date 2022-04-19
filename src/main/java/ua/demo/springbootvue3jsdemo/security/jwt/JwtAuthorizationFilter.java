package ua.demo.springbootvue3jsdemo.security.jwt;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;


public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_BEARER_PREFIX = "Bearer ";

    private String loginUrl;

    private final JwtHmac256Helper jwtHmac256Helper;

    public JwtAuthorizationFilter(JwtHmac256Helper jwtHmac256Helper) {
        this.jwtHmac256Helper = jwtHmac256Helper;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {


        if (Objects.equals(request.getServletPath(), loginUrl)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            UsernamePasswordAuthenticationToken authenticationToken = obtainAuthenticationToken(request);
            if (authenticationToken == null) {
                filterChain.doFilter(request, response);
                return;
            }

            if (authenticationIsRequired(authenticationToken.getName())) {
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(authenticationToken);
                SecurityContextHolder.setContext(context);
            }

        } catch (AuthenticationException e) {

            SecurityContextHolder.clearContext();

            this.logger.debug("Failed to process authentication request", e);

            response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());

            return;
        }

        filterChain.doFilter(request, response);
    }


    private UsernamePasswordAuthenticationToken obtainAuthenticationToken(HttpServletRequest request) {

        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader == null || !authorizationHeader.startsWith(AUTHORIZATION_BEARER_PREFIX)) {
            return null;
        }

        String jwtToken = authorizationHeader.substring(AUTHORIZATION_BEARER_PREFIX.length());

        return jwtHmac256Helper.verifyToken(jwtToken);
    }

    private boolean authenticationIsRequired(String username) {

        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
        if (existingAuth == null || !existingAuth.isAuthenticated()) {
            return true;
        }

        return existingAuth instanceof UsernamePasswordAuthenticationToken && !existingAuth.getName().equals(username);
    }


    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }
}
