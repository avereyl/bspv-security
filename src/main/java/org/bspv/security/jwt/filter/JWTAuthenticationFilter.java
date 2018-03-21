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

import org.bspv.security.jwt.TokenValidationService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

/**
 */
public class JWTAuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {

    private final TokenValidationService validationService;

    /**
     */
    public JWTAuthenticationFilter(TokenValidationService validationService) {
        super();
        this.validationService = validationService;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest,
     * javax.servlet.ServletResponse, javax.servlet.FilterChain)
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {
        Authentication authentication = this.validationService.validateAuthToken((HttpServletRequest) request);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        // Unused (AbstractPreAuthenticatedProcessingFilter is used for its place in the
        // filter chain)
        // TODO might properly override this method instead of overriding doFilter
        return null;
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        // Unused (AbstractPreAuthenticatedProcessingFilter is used for its place in the
        // filter chain)
        // TODO might properly override this method instead of overriding doFilter
        return null;
    }

}
