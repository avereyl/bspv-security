/**
 * 
 */
package org.bspv.security.jwt.filter;

import java.io.IOException;
import java.util.Collections;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bspv.security.common.AccountCredentials;
import org.bspv.security.jwt.TokenAuthenticationService;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 *
 */
public class JWTLoginFilter extends AbstractAuthenticationProcessingFilter {

    private final TokenAuthenticationService authenticationService;

    public JWTLoginFilter(String url, AuthenticationManager authManager,
            TokenAuthenticationService authenticationService) {
        super(new AntPathRequestMatcher(url, HttpMethod.POST.name()));
        setAuthenticationManager(authManager);
        this.authenticationService = authenticationService;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter#attemptAuthentication(
     * javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res)
            throws AuthenticationException, IOException, ServletException {
        AccountCredentials creds = new ObjectMapper().readValue(req.getInputStream(), AccountCredentials.class);
        return getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(creds.getUsername(),
                creds.getPassword(), Collections.emptyList()));
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter#successfulAuthentication(
     * javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, javax.servlet.FilterChain,
     * org.springframework.security.core.Authentication)
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, FilterChain chain,
            Authentication auth) throws IOException, ServletException {
        this.authenticationService.addAuthenticationToken(req, res, (UserDetails) auth.getPrincipal());
    }

}
