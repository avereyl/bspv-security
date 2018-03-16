/**
 * 
 */
package org.bspv.security.jwt;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bspv.security.jwt.mapper.TokenToUserDetailsMapper;
import org.bspv.security.jwt.tokenwriter.TokenWriter;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.TextCodec;
import lombok.extern.slf4j.Slf4j;

/**
 *
 */
@Slf4j
@Service
public class TokenGenerationService implements InitializingBean {

    @Autowired
    private TokenGeneratorProperties properties;

    @SuppressWarnings("rawtypes")
    @Autowired
    private TokenToUserDetailsMapper tokenToUserDetailsMapper;

    @Autowired
    private final List<TokenWriter> tokenWriters = new ArrayList<>();

    /**
     * 
     * @param response
     * @param userDetails
     */
    public void addAuthenticationToken(HttpServletRequest request, HttpServletResponse response,
            UserDetails userDetails) {
        LocalDateTime now = LocalDateTime.now();
        Date expirationDate = Date
                .from(now.toInstant(ZoneOffset.UTC).plusMillis(properties.getDefaultExpirationTime()));
        @SuppressWarnings("unchecked")
        Claims claims = tokenToUserDetailsMapper.toClaims(userDetails);
        SignatureAlgorithm algorithm = SignatureAlgorithm.forName(this.properties.getSignatureAlgorithmName());
//		@formatter:off
		String jwt = Jwts
 				.builder()
 				.setClaims(claims)
 				.setIssuedAt(Date.from(now.toInstant(ZoneOffset.UTC)))
				.setExpiration(expirationDate)
				.signWith(algorithm, TextCodec.BASE64.encode(this.properties.getSecret()))
				.compact();
//		@formatter:on
        writeToken(jwt, request, response);
    }

    /**
     * Write the token to the response. Use defined {@link TokenWriter}s.
     * 
     * @param jwt
     *            The token to write
     * @param request
     *            The HTTP request
     * @param response
     *            The HTTP response
     */
    protected void writeToken(String jwt, HttpServletRequest request, HttpServletResponse response) {
        
        String preferredTokenWriterName = findTokenWriterPreference(request);
        TokenWriter preferredWriter = this.tokenWriters.stream().filter(w -> w.supports(preferredTokenWriterName)).findFirst().orElse(null);
        if (preferredWriter != null) {
            response.addHeader("Preference-Applied", preferredTokenWriterName);
            preferredWriter.write(jwt, response);
        } else {
            log.warn("Impossible to apply client preference : {} for jwt", preferredTokenWriterName);
            tokenWriters.get(0).write(jwt, response);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
     */
    @Override
    public void afterPropertiesSet() throws Exception {
        // warn if no token writer is found
        if (tokenWriters.isEmpty()) {
            log.error("No token writers found -> no way to write JWT authorization credentials.");
            throw new NoSuchBeanDefinitionException(TokenWriter.class, "No writer bean defined for token.");
        }

    }


    /**
     * Finding a {@link TokenWriter} preference from the request.
     * Handling client expectation regarding the way to send the token back (jwt=cookie,jwt=payload)
     * @param req The HTTP request
     * @return A String representing a token writer or an epmty string if no preference
     */
    private String findTokenWriterPreference(HttpServletRequest req) {
        String tokenWriterPref = "";
        String preferHeader = req.getHeader("Prefer");
        if (!StringUtils.isEmpty(preferHeader)) {// some preferences exists
// @formatter:off
            tokenWriterPref = Arrays.asList(preferHeader.split(";")).stream()
                    .filter(preference -> preference.trim().startsWith("jwt="))
                    .findFirst()
                    .map(channelName -> channelName.substring(4).toUpperCase())
                    .orElse("");
// @formatter:on
        }
        return tokenWriterPref;
    }

}
