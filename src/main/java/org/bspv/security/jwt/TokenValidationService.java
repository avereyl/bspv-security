package org.bspv.security.jwt;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.bspv.security.jwt.mapper.TokenToUserDetailsMapper;
import org.bspv.security.jwt.tokenreader.TokenReader;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.TextCodec;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class TokenValidationService implements InitializingBean {

    @Autowired
    private final List<TokenReader> tokenFinders = new ArrayList<>();
    
    @Autowired
    private TokenValidatorProperties properties;
    
    @SuppressWarnings("rawtypes")
    @Autowired
    private TokenToUserDetailsMapper tokenToUserDetailsMapper;

    @Override
    public void afterPropertiesSet() throws Exception {
        // warn if no token reader is found
        if (tokenFinders.isEmpty()) {
            log.error("No token reader found -> no way to read JWT authorization credentials.");
            throw new NoSuchBeanDefinitionException(TokenReader.class, "No reader bean defined for token.");
        }
    }

    /**
     * 
     * @param request
     * @return
     */
    public Authentication validateAuthToken(HttpServletRequest request) {

        // load authorization token
        Authentication result = null;
        String token = findToken(request);
        if (!StringUtils.isEmpty(token)) {
            try {
                // check claims validity
                Claims claims = Jwts
                        .parser()
                        .setSigningKey(TextCodec.BASE64.encode(this.properties.getSecret()))
                        .parseClaimsJws(token)
                        .getBody();

                // build userDetails from claims
                UserDetails user = tokenToUserDetailsMapper.toUserDetails(claims);
                if (user != null) {
                    result = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                }
            } catch (Exception e) {
                log.warn("Invalid JWT Token", e);
            }
        }
        return result;
    }

    /**
     * Try to load the JWT token from the request. Use defined {@link TokenReader}s.
     * 
     * @param request
     *            The request
     * @return The JWT token if any, an empty string otherwise
     */
    public String findToken(HttpServletRequest request) {
        return this.tokenFinders.stream().map(finder -> finder.find(request))
                .filter(token -> !StringUtils.isEmpty(token)).findFirst().orElse("");
    }

}
