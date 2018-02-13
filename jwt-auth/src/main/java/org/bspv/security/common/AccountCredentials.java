/**
 * 
 */
package org.bspv.security.common;

import lombok.Getter;
import lombok.Setter;

/**
 *
 */
@Getter
@Setter
public class AccountCredentials {

	private String username;
	private String password;
	private String preferredAuthTokenReturnChannel = "";
}
