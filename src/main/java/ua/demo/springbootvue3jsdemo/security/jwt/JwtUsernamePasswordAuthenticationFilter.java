package ua.demo.springbootvue3jsdemo.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

public class JwtUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final JwtHmac256Helper jwtHmac256Helper;
    private final ObjectMapper objectMapper;

    public JwtUsernamePasswordAuthenticationFilter(AuthenticationManager authenticationManager, JwtHmac256Helper jwtHmac256Helper, ObjectMapper objectMapper) {
        super(authenticationManager);
        this.jwtHmac256Helper = jwtHmac256Helper;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authentication) throws IOException {

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String token = jwtHmac256Helper.createToken(userDetails);

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        PrintWriter responseWriter = response.getWriter();

        objectMapper.writeValue(responseWriter, Map.of("token", token));

        responseWriter.flush();
    }
}
