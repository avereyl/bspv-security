/**
 *
 */
package org.bspv.security.jwt.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.bspv.security.jwt.TokenAuthenticationService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

/**
 */
public class JWTAuthenticationFilter extends GenericFilterBean {

    private final TokenAuthenticationService authenticationService;

    /**
     */
    public JWTAuthenticationFilter(TokenAuthenticationService authenticationService) {
        super();
        this.authenticationService = authenticationService;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse,
     * javax.servlet.FilterChain)
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {

        Authentication authentication = this.authenticationService.checkAuthentication((HttpServletRequest) request);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);

    }

}
