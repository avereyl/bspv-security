/**
 * 
 */
package org.bspv.security.jwt.mapper;

import org.springframework.security.core.userdetails.UserDetails;

import io.jsonwebtoken.Claims;

/**
 *
 */
public interface TokenToUserDetailsMapper<T extends UserDetails> {
	
	T toUserDetails(final Claims claims);
	
	Claims toClaims(final T userDetails);
}
