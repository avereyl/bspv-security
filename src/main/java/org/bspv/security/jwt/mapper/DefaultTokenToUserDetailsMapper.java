/**
 * 
 */
package org.bspv.security.jwt.mapper;

import java.util.List;
import java.util.stream.Collectors;

import org.bspv.security.Constants;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

/**
 *
 */
public class DefaultTokenToUserDetailsMapper implements TokenToUserDetailsMapper<UserDetails> {
	
    /*
	 * (non-Javadoc)
	 * @see org.bspv.security.jwt.TokenToUserDetailsMapper#toUserDetails(io.jsonwebtoken.Claims)
	 */
	@Override
	public UserDetails toUserDetails(final Claims claims) {
		@SuppressWarnings("unchecked")
		List<String> scopes = claims.get(Constants.AUTHORITIES_CLAIM_NAME, List.class);
		List<GrantedAuthority> authorities = scopes
				.stream()
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());
		return new User(claims.getSubject(), null, authorities);
	}

	/*
	 * (non-Javadoc)
	 * @see org.bspv.security.jwt.TokenToUserDetailsMapper#toClaims(org.springframework.security.core.userdetails.UserDetails)
	 */
	@Override
	public Claims toClaims(final UserDetails userDetails) {
		Claims claims = Jwts.claims().setSubject(userDetails.getUsername());
		List<String> scopes = userDetails.getAuthorities()
				.stream()
				.map(Object::toString)
				.collect(Collectors.toList());
		claims.put(Constants.AUTHORITIES_CLAIM_NAME, scopes);
		return claims;
	}
	
	

}
