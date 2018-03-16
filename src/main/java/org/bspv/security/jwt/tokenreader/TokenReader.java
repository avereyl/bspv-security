/**
 * 
 */
package org.bspv.security.jwt.tokenreader;

import javax.servlet.http.HttpServletRequest;

/**
 *
 */
public interface TokenReader {

	String find(HttpServletRequest request);
	
}
