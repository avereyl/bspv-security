/**
 *
 */
package org.bspv.security.jwt;

import java.io.Serializable;
import java.util.Map;

import lombok.Getter;
import lombok.Setter;

/**
 * Properties class to store {@link TokenGenerationService} configuration.
 */
@Getter
@Setter
public class TokenGeneratorProperties extends TokenProcessorProperties implements Serializable {

	/**
	 * Generated serialVersionUID.
	 */
	private static final long serialVersionUID = -3030079996395887689L;

	/**
	 * Value of the secret set in application*.properties.
	 * TODO change to use asymmetric keys
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
