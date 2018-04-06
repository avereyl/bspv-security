package org.bspv.security.jwt.mapper;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.bspv.security.jwt.mapper.TokenToUserDetailsMapper;
import org.bspv.security.model.ServiceGrantedAuthority;
import org.bspv.security.model.User;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class TokenToUserMapper implements TokenToUserDetailsMapper<User> {

    public static final String USER_ID_CLAIM_NAME = "id";
    public static final String VERSION_CLAIM_NAME = "version";
    public static final String EMAIL_CLAIM_NAME = "email";
    public static final String AUTHORITIES_CLAIM_NAME = "scopes";

    /*
     * (non-Javadoc)
     * 
     * @see org.bspv.security.jwt.mapper.TokenToUserDetailsMapper#toUserDetails(io.
     * jsonwebtoken.Claims)
     */
    @Override
    @SuppressWarnings("unchecked")
    public User toUserDetails(Claims claims) {
        List<Map<String, Object>> scopes = claims.get(AUTHORITIES_CLAIM_NAME, List.class);
        List<ServiceGrantedAuthority> authorities = scopes
                .stream()
                .flatMap(scope -> ((List<String>)(scope.get(ServiceAuthoritiesWrapper.AUTHORITIES_NAME)))
                        .stream()
                        .map(auth -> new ServiceGrantedAuthority(scope.get(ServiceAuthoritiesWrapper.SERVICE_NAME).toString(), new SimpleGrantedAuthority(auth.toString())))
                        ).collect(Collectors.toList());
        return User.builder().id(UUID.fromString(claims.get(USER_ID_CLAIM_NAME, String.class)))
                .username(claims.getSubject()).email(claims.get(EMAIL_CLAIM_NAME, String.class))
                .authorities(authorities)
                .version(claims.get(VERSION_CLAIM_NAME, Integer.class).longValue()).build();
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.bspv.security.jwt.mapper.TokenToUserDetailsMapper#toClaims(org.
     * springframework.security.core.userdetails.UserDetails)
     */
    @Override
    public Claims toClaims(User user) {
        Claims claims = Jwts.claims().setSubject(user.getUsername());
        claims.put(USER_ID_CLAIM_NAME, user.getId().toString());
        claims.put(VERSION_CLAIM_NAME, user.getVersion());
        claims.put(EMAIL_CLAIM_NAME, user.getEmail());
        Map<String, List<String>> scopesMap = new HashMap<>();
        user.getAuthorities().stream().forEach(sga -> {
            if (scopesMap.containsKey(sga.getService())) {
                scopesMap.get(sga.getService()).add(sga.getAuthority());
            } else {
                scopesMap.put(sga.getService(), Arrays.asList(sga.getAuthority()));
            }
        });
        List<ServiceAuthoritiesWrapper> scopes = scopesMap.entrySet().stream()
                .map(e -> new ServiceAuthoritiesWrapper(e.getKey(), e.getValue().toArray(new String[0])))
                .collect(Collectors.toList());

        claims.put(AUTHORITIES_CLAIM_NAME, scopes);
        return claims;
    }

}
