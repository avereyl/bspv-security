/**
 * 
 */
package org.bspv.security.jwt.tokenwriter;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.bspv.security.jwt.TokenProcessorProperties;
import org.springframework.beans.factory.annotation.Autowired;

/**
 *
 */
public class CookieTokenWriter implements TokenWriter {

	@Autowired
	private TokenProcessorProperties properties;
	
	/*
	 * (non-Javadoc)
	 * @see org.bspv.security.jwt.tokenwriter.TokenWriter#write(java.lang.String, javax.servlet.http.HttpServletResponse)
	 */
	@Override
	public void write(String token, HttpServletResponse response) {
		Cookie cookie = new Cookie(properties.getAuthorizationCookieName(), token);
		cookie.setSecure(true);
		cookie.setHttpOnly(true);
		response.addCookie(cookie);
	}


}
