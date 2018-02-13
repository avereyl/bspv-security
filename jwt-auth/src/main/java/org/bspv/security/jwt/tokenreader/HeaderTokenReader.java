/**
 * 
 */
package org.bspv.security.jwt.tokenreader;

import javax.servlet.http.HttpServletRequest;

import org.bspv.security.jwt.TokenProcessorProperties;
import org.springframework.beans.factory.annotation.Autowired;

/**
 *
 */
public class HeaderTokenReader implements TokenReader {
    

	private static final String TOKEN_PREFIX = "Bearer ";
	
    @Autowired
	private TokenProcessorProperties properties;
	
	/*
	 * (non-Javadoc)
	 * @see org.bspv.security.jwt.finder.TokenFinder#find(javax.servlet.http.HttpServletRequest)
	 */
	@Override
	public String find(HttpServletRequest request) {
		String authorizationHeader = request.getHeader(properties.getAuthorizationHeaderName());
		return authorizationHeader != null ? authorizationHeader.replace(TOKEN_PREFIX, "") : "";
	}


}
