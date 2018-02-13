package org.bspv.security.jwt.autoconfigure;
/**
 * 
 */

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Constant class.
 * 
 * 
 */
public final class SecurityDefaultData {

	/** Admin authority. */
	public static final GrantedAuthority ROLE_ADMIN = new SimpleGrantedAuthority("ROLE_ADMIN");
	/** User authority. */
	public static final GrantedAuthority ROLE_USER = new SimpleGrantedAuthority("ROLE_USER");
	/** Guest authority. */
	public static final GrantedAuthority ROLE_GUEST = new SimpleGrantedAuthority("ROLE_GUEST");

	// @formatter:off
	public static final UserDetails ADMIN = new User("admin",
			"$2a$11$Yv438nPygzN75ig5uQmM0OtKask6hto5PgDhSex4veCOgqXua0wCm", 
			Arrays.asList(
					SecurityDefaultData.ROLE_ADMIN,
					SecurityDefaultData.ROLE_USER,
					SecurityDefaultData.ROLE_GUEST));

	public static final UserDetails ALICE = new User("alice",
			"$2a$11$On3nIbO/L36aCsWbOsD.mOv6QDxD438i0aJZTxeZhGV1VO1WpdEGq",
			Arrays.asList(
			        SecurityDefaultData.ROLE_USER,
			        SecurityDefaultData.ROLE_GUEST));

	public static final UserDetails BOB = new User("bob",
			"$2a$11$PtaSn51Z9YMIwlU71MtaDuA4Lrn9LdMHFkI9QyDk3n7veWdXSpnHK",
			Arrays.asList(
			        SecurityDefaultData.ROLE_USER,
			        SecurityDefaultData.ROLE_GUEST));

	public static final UserDetails GUEST = new User("guest",
			"$2a$11$tUOOhGI1DSM3qrFOMF6jx.e0JWkytg8A4MjeJV0wpDi.7pfR1e30i",
			Arrays.asList(
			        SecurityDefaultData.ROLE_GUEST));
	// @formatter:on

	public static final List<UserDetails> USERS = Collections.unmodifiableList(
	        Arrays.asList(
	                SecurityDefaultData.ADMIN,
	                	SecurityDefaultData.ALICE,
	                	SecurityDefaultData.BOB,
	                	SecurityDefaultData.GUEST));

	/**
	 * Private constructor.
	 */
	private SecurityDefaultData() {
	}
}
