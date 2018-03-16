/**
 *
 */
package org.bspv.security.jwt;

import java.io.Serializable;

import lombok.Getter;
import lombok.Setter;

/**
 * Properties class to store {@link TokenValidationService} configuration.
 */
@Getter
@Setter
public class TokenValidatorProperties implements Serializable {

	/**
	 * Generated serialVersionUID.
	 */
    private static final long serialVersionUID = 943926683399261736L;
    
    /**
	 * Value of the secret set in application*.properties.
	 * TODO change to use asymmetric keys
	 */
	private String secret;
	

}