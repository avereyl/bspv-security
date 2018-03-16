/**
 * 
 */
package org.bspv.security.jwt.tokenwriter;

import javax.servlet.http.HttpServletResponse;

/**
 *
 */
public interface TokenWriter {

	void write(String token, HttpServletResponse response);
	
	default boolean supports(String channel) {
	    return this.getClass().getSimpleName().replace("TokenWriter", "").equalsIgnoreCase(channel);
	}
	
}
