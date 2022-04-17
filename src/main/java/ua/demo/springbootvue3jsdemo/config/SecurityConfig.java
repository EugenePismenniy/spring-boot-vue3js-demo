package ua.demo.springbootvue3jsdemo.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import ua.demo.springbootvue3jsdemo.security.filters.JwtHmac256Helper;
import ua.demo.springbootvue3jsdemo.security.filters.JwtUsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    static final String LOGIN_URL = "/api/v1/login";


    private final JwtHmac256Helper jwtHmac256Helper;
    private final ObjectMapper objectMapper;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user1")
                .password("{noop}123")
                .roles("USER", "ADMIN");
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(STATELESS);
        http.authorizeRequests().antMatchers(LOGIN_URL).permitAll();
        http.authorizeRequests().anyRequest().authenticated();
        http.addFilter(jwtUsernamePasswordAuthenticationFilter());

    }


    @Bean
    public JwtUsernamePasswordAuthenticationFilter jwtUsernamePasswordAuthenticationFilter() throws Exception {
        JwtUsernamePasswordAuthenticationFilter filter = new JwtUsernamePasswordAuthenticationFilter(authenticationManagerBean(), jwtHmac256Helper, objectMapper);
        filter.setFilterProcessesUrl(LOGIN_URL);
        return filter;
    }

}
