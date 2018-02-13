/**
 * 
 */
package org.bspv.security.jwt.tokenreader;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.bspv.security.jwt.TokenProcessorProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.util.WebUtils;

/**
 *
 */
public class CookieTokenReader implements TokenReader {

	@Autowired
	private TokenProcessorProperties properties;
	
	/*
	 * (non-Javadoc)
	 * 
	 * @see org.bspv.security.jwt.finder.TokenFinder#find(javax.servlet.http.HttpServletRequest)
	 */
	@Override
	public String find(HttpServletRequest request) {
		Cookie authorizationCookie = WebUtils.getCookie(request, properties.getAuthorizationCookieName());
		return (authorizationCookie != null) ? authorizationCookie.getValue() : "";
	}

}
