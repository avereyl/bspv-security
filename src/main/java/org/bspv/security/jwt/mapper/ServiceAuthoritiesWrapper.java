package org.bspv.security.jwt.mapper;

public class ServiceAuthoritiesWrapper {
    
    public static final String SERVICE_NAME = "service";
    public static final String AUTHORITIES_NAME = "authorities";

    private final String service;
    private final String[] authorities;
    
    public ServiceAuthoritiesWrapper(String service, String[] authorities) {
        super();
        this.service = service;
        this.authorities = authorities;
    }

    public String getService() {
        return service;
    }

    public String[] getAuthorities() {
        return authorities;
    }
    
}
