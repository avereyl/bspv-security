package org.bspv.security.config;

import org.bspv.security.jwt.TokenValidationService;
import org.bspv.security.jwt.TokenValidatorProperties;
import org.bspv.security.jwt.filter.JWTAuthenticationFilter;
import org.bspv.security.jwt.filter.JWTLoginFilter;
import org.bspv.security.jwt.mapper.DefaultTokenToUserDetailsMapper;
import org.bspv.security.jwt.mapper.TokenToUserDetailsMapper;
import org.bspv.security.jwt.tokenreader.CookieTokenReader;
import org.bspv.security.jwt.tokenreader.HeaderTokenReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.RegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * This class is responsible for declaring
 * <ul>
 * <li>JWT authentication filter
 * <li>JWT readers (from http header / cookie)
 * </ul>
 * 
 * @see JWTAuthenticationFilter
 * @see HeaderTokenReader
 * @see CookieTokenReader
 *
 */

@Configuration
public class JwtFilterConfiguration {

    @Configuration
    public static class TokenHandlingDefaultConfiguration {

        /**
         * Default mapper between JWT token and {@link UserDetails} implementation.
         * 
         * To be overridden to map to a specific UserDetails implementation.
         * 
         * @return
         */
        @Bean
        @ConditionalOnMissingBean(TokenToUserDetailsMapper.class)
        public TokenToUserDetailsMapper<UserDetails> tokenToUserDetailsMapper() {
            return new DefaultTokenToUserDetailsMapper();
        }

        /**
         * Token reader for HTTP headers. Enable by default.
         */
        @Bean
        @Order(Ordered.LOWEST_PRECEDENCE - 1)
        @ConditionalOnMissingBean(HeaderTokenReader.class)
        @ConditionalOnProperty(value = "security.jwt.header-token-reader.enabled", matchIfMissing = true)
        public HeaderTokenReader headerTokenReader() {
            return new HeaderTokenReader();
        }

        /**
         * Token reader for HTTP cookies. Enable by default.
         */
        @Bean
        @Order(Ordered.LOWEST_PRECEDENCE)
        @ConditionalOnMissingBean(CookieTokenReader.class)
        @ConditionalOnProperty(value = "security.jwt.cookie-token-reader.enabled", matchIfMissing = true)
        public CookieTokenReader cookieTokenReader() {
            return new CookieTokenReader();
        }
    }

    /**
     * 
     */
    @Order(2)
    @Configuration
    @EnableGlobalMethodSecurity(securedEnabled=true, prePostEnabled = true)
    public static class SecurityConfiguration extends WebSecurityConfigurerAdapter {

        @Autowired
        public UserDetailsService userDetailsService;

        /*
         * (non-Javadoc)
         * 
         * @see org.springframework.security.config.annotation.web.configuration.
         * WebSecurityConfigurerAdapter #configure(org.springframework.security.config
         * .annotation.web.builders.HttpSecurity)
         */
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // @formatter:off
             http
                 .requestMatchers().anyRequest().and()
             // filter requests to check the presence of JWT
                 .addFilter(new JWTAuthenticationFilter(tokenValidationService()))
                 .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                 .csrf().disable()
                 .anonymous().disable()
                 .authorizeRequests()
                     .antMatchers(HttpMethod.GET, "/").permitAll()
                     .anyRequest().fullyAuthenticated()
                 ;
            // @formatter:on
        }
        
        /**
         * Prevent the {@link JWTLoginFilter} to be also registered as a servlet filter.
         * @param filter
         * @return
         */
        @Bean
//        @ConditionalOnBean(value = JWTLoginFilter.class)
        public RegistrationBean jwtLoginFilterRegister(JWTLoginFilter filter) {
            FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
            registrationBean.setEnabled(false);
            return registrationBean;
        }

        /**
         * Properties for a JWT token processor.
         *
         * @return {@link JwtTokenProcessorProperties}
         */
        @Bean
        @ConfigurationProperties(prefix = "bspv.security.jwt")
        public TokenValidatorProperties jwtTokenValidatorProperties() {
            return new TokenValidatorProperties();
        }

        /**
         * 
         * @return
         */
        @Bean
        public TokenValidationService tokenValidationService() {
            return new TokenValidationService();
        }

    }
}
