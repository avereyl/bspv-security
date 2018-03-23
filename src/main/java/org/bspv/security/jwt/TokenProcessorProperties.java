package org.bspv.security.jwt;

import java.io.Serializable;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TokenProcessorProperties implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = 6006637418573041462L;

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

}
