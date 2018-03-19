package org.bspv.security.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bspv.security.common.CustomUserCache;
import org.bspv.security.common.InMemoryReadOnlyUserDetailsService;
import org.bspv.security.jwt.TokenGenerationService;
import org.bspv.security.jwt.TokenGeneratorProperties;
import org.bspv.security.jwt.filter.JWTLoginFilter;
import org.bspv.security.jwt.mapper.DefaultTokenToUserDetailsMapper;
import org.bspv.security.jwt.mapper.TokenToUserDetailsMapper;
import org.bspv.security.jwt.tokenwriter.CookieTokenWriter;
import org.bspv.security.jwt.tokenwriter.PayloadTokenWriter;
import org.bspv.security.jwt.tokenwriter.TokenWriter;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cache.support.SimpleCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * This class is responsible for declaring
 * <ul>
 * <li>JWT login filter
 * <li>JWT writer (to http header / request paylod)
 * <li>UserDetailsService user by AuthenticationProvider
 * </ul>
 * 
 * @see JWTLoginFilter
 * @see PayloadTokenWriter
 * @see CookieTokenWriter
 *
 */
@Configuration
public class JwtServerConfiguration implements InitializingBean {

    @Value("${bspv.security.fallback.username:admin}")
    private String fallbackAdminUsername;
    @Value("${bspv.security.fallback.password:admin}")
    private String fallbackAdminPassword;
    
    @Autowired
    private final List<UserDetails> fallbackAdminUsers = new ArrayList<>();

    @Configuration
    public class TokenHandlingDefaultConfiguration {

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
         * Token writer into HTTP cookies. Enable by default.
         */
        @Bean
        @Order(Ordered.LOWEST_PRECEDENCE - 1)
        @ConditionalOnMissingBean(CookieTokenWriter.class)
        @ConditionalOnProperty(value = "security.jwt.cookie-token-writer.enabled", matchIfMissing = true)
        public TokenWriter cookieTokenWriter() {
            return new CookieTokenWriter();
        }

        /**
         * Token writer into HTTP request payload. Enable by default.
         */
        @Bean
        @Order(Ordered.LOWEST_PRECEDENCE)
        @ConditionalOnMissingBean(PayloadTokenWriter.class)
        @ConditionalOnProperty(value = "security.jwt.payload-token-writer.enabled", matchIfMissing = true)
        public TokenWriter payloadTokenWriter() {
            return new PayloadTokenWriter();
        }
    }

    /**
     * 
     */
    @EnableWebSecurity
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    @Order(1)
    class SecurityConfiguration extends WebSecurityConfigurerAdapter {

        @Autowired
        public UserDetailsService userDetailsService;

        /*
         * (non-Javadoc)
         * 
         * @see org.springframework.security.config.annotation.web.configuration.
         * WebSecurityConfigurerAdapter #configure(org.springframework.security.config
         * .annotation.authentication.builders.AuthenticationManagerBuilder)
         */
        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            if (this.userDetailsService != null) {
                // authentication provider using the provided userDetailsService (if any)
                DaoAuthenticationProvider defaultAuthenticationProvider = new DaoAuthenticationProvider();
                defaultAuthenticationProvider.setUserDetailsService(this.userDetailsService);
                defaultAuthenticationProvider.setPasswordEncoder(new BCryptPasswordEncoder(11));
                auth.authenticationProvider(defaultAuthenticationProvider);
            }
            // authentication provider using the default fallback admin account (always)
            DaoAuthenticationProvider fallbackAuthenticationProvider = new DaoAuthenticationProvider();
            fallbackAuthenticationProvider.setUserDetailsService(new InMemoryReadOnlyUserDetailsService(fallbackAdminUsers));
            fallbackAuthenticationProvider.setPasswordEncoder(new BCryptPasswordEncoder(11));
            auth.authenticationProvider(fallbackAuthenticationProvider);
        }

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
             http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
                 .and()
                 .csrf().disable()
                 .anonymous().disable()
                 .authorizeRequests()
                 .antMatchers(HttpMethod.GET, "/").permitAll()
                 .anyRequest().fullyAuthenticated().and()
                 // We filter here the login requests
                 .addFilterBefore(new JWTLoginFilter("/login", authenticationManager(), tokenAuthenticationService()),
                         UsernamePasswordAuthenticationFilter.class);
            // @formatter:on
        }

        /**
         * Properties for a JWT token processor.
         *
         * @return {@link JwtTokenProcessorProperties}
         */
        @Bean
        @ConfigurationProperties(prefix = "bspv.security.jwt")
        public TokenGeneratorProperties jwtTokenProcessorProperties() {
            return new TokenGeneratorProperties();
        }

        /**
         * 
         * @return
         */
        @Bean
        public TokenGenerationService tokenAuthenticationService() {
            return new TokenGenerationService();
        }

        /**
         * ???
         */
        @Override
        protected UserDetailsService userDetailsService() {
            return this.userDetailsService;
        }

    }

    @Configuration
    @ConditionalOnProperty("bspv.security.usercache.enabled")
    public class UserCacheAutoConfiguration {

        /**
         * Cache manager used by the application.
         *
         * {@link User} are cached.
         *
         * @return a cache manager
         */
        @Bean
        public CacheManager cacheManager() {
            // configure and return an implementation of Spring's CacheManager SPI
            final SimpleCacheManager cacheManager = new SimpleCacheManager();
            cacheManager.setCaches(Arrays.asList(new ConcurrentMapCache(CustomUserCache.USER_CACHE_NAME)));
            return cacheManager;
        }

        /**
         * User's cache definition, the injected {@link CacheManager}.
         * 
         * @return A User cache
         * @throws Exception
         */
        @Bean
        public UserCache userCache(final CacheManager cacheManager) {
            return new CustomUserCache(cacheManager.getCache(CustomUserCache.USER_CACHE_NAME));
        }

    }

    @Override
    public void afterPropertiesSet() throws Exception {
//      @formatter:off
        if (this.fallbackAdminUsers == null || this.fallbackAdminUsers.isEmpty()) {
            this.fallbackAdminUsers.add(
                    new User(fallbackAdminUsername, 
                            new BCryptPasswordEncoder(11).encode(fallbackAdminPassword),
                            Arrays.asList(new SimpleGrantedAuthority("ADMIN")
                                    )));
        }
//      @formatter:on
    }

}
