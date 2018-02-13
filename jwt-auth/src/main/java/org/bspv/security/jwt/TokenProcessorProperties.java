/**
 *
 */
package org.bspv.security.jwt;

import java.io.Serializable;
import java.util.Map;

import lombok.Getter;
import lombok.Setter;

/**
 * Properties class to store {@link JwtTokenProcessor} configuration.
 */
@Getter
@Setter
public class TokenProcessorProperties implements Serializable {

	/**
	 * Generated serialVersionUID.
	 */
	private static final long serialVersionUID = -3030079996395887689L;

	/**
	 * Value of the secret set in application*.properties.
	 */
	private String secret;
	
	/**
	 * Name of the signature algorithm.
	 */
	private String signatureAlgorithmName = "HS256";

	/**
	 * Max expiration times in seconds for a given granted authority.
	 */
	private Map<String, Integer> expirationTime;

	/**
	 * Default expiration times in milliseconds.
	 */
	private Integer defaultExpirationTime = 1_800_000; //30 minutes

	/**
	 * Header name storing the JWT.
	 */
	private String authorizationHeaderName = "Authorization";
	
	/**
	 * Cookie name storing the JWT.
	 */
	private String authorizationCookieName = "AuthorizationCookie";
	
	/**
	 * Parameter name storing the JWT.
	 */
	private String authorizationParameterName = "authorization";
	
	/**
	 * Default channel to send back the authorization token.
	 * COOKIE, HEADER, PAYLOAD
	 */
	private CHANNEL defaultAuthorizationTokenChannel = CHANNEL.HEADER;
	
	/**
	 * 
	 *
	 */
	public enum CHANNEL {
		COOKIE, HEADER, PAYLOAD
	}

}
