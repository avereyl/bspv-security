/**
 * 
 */
package org.bspv.security.jwt.autoconfigure;

import java.util.Arrays;

import org.bspv.security.common.CustomUserCache;
import org.bspv.security.jwt.TokenAuthenticationService;
import org.bspv.security.jwt.TokenProcessorProperties;
import org.bspv.security.jwt.filter.JWTAuthenticationFilter;
import org.bspv.security.jwt.filter.JWTLoginFilter;
import org.bspv.security.jwt.mapper.DefaultTokenToUserDetailsMapper;
import org.bspv.security.jwt.mapper.TokenToUserDetailsMapper;
import org.bspv.security.jwt.tokenreader.CookieTokenReader;
import org.bspv.security.jwt.tokenreader.HeaderTokenReader;
import org.bspv.security.jwt.tokenwriter.CookieTokenWriter;
import org.bspv.security.jwt.tokenwriter.PayloadTokenWriter;
import org.bspv.security.jwt.tokenwriter.TokenWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
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
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 *
 */
@Configuration
@ConditionalOnClass({ JWTAuthenticationFilter.class })
@AutoConfigureBefore(org.springframework.boot.autoconfigure.security.SecurityAutoConfiguration.class)
public class SecurityAutoConfiguration {

    /**
     * 
     */
    @EnableWebSecurity
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    class SecurityConfiguration extends WebSecurityConfigurerAdapter {

        @Autowired
        public UserDetailsService userDetailsService;

        /*
         * (non-Javadoc)
         * 
         * @see org.springframework.security.config.annotation.web.configuration. WebSecurityConfigurerAdapter
         * #configure(org.springframework.security.config
         * .annotation.authentication.builders.AuthenticationManagerBuilder)
         */
        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
            authenticationProvider.setUserDetailsService(this.userDetailsService);
            authenticationProvider.setPasswordEncoder(new BCryptPasswordEncoder(11));
            auth.authenticationProvider(authenticationProvider);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.springframework.security.config.annotation.web.configuration. WebSecurityConfigurerAdapter
         * #configure(org.springframework.security.config .annotation.web.builders.HttpSecurity)
         */
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // @formatter:off
			 http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
			     .and().csrf().disable()
			     .authorizeRequests()
			     .antMatchers("/").permitAll()
			     .antMatchers(HttpMethod.POST, "/login").permitAll()
			     .anyRequest().authenticated()
			     .and()
			     // We filter the api/login requests
			     .addFilterBefore(new JWTLoginFilter("/login", authenticationManager(), tokenAuthenticationService()),
			             UsernamePasswordAuthenticationFilter.class)
			     // And filter other requests to check the presence of JWT
			     .addFilterBefore(new JWTAuthenticationFilter(tokenAuthenticationService()),
			             UsernamePasswordAuthenticationFilter.class);
			// @formatter:on
        }

        /**
         * Properties for a JWT token processor.
         *
         * @return {@link JwtTokenProcessorProperties}
         */
        @Bean
        @ConfigurationProperties(prefix = "security.jwt")
        public TokenProcessorProperties jwtTokenProcessorProperties() {
            return new TokenProcessorProperties();
        }

        /**
         * 
         * @return
         */
        @Bean
        public TokenAuthenticationService tokenAuthenticationService() {
            return new TokenAuthenticationService();
        }

        /**
         * 
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

    /**
     * 
     *
     */
    @Configuration
    public class UserDetailsServiceDefaultConfiguration {

        @Bean
        @ConditionalOnMissingBean(UserDetailsService.class)
        public UserDetailsService userDetailsService() {
            return new InMemoryUserDetailsManager(SecurityDefaultData.USERS);
        }

    }

    /**
     * 
     *
     */
    @Configuration
    public class TokenHandlingDefaultConfiguration {
        /**
         * To be overridden to map to a specific user class
         * 
         * @return
         */
        @Bean
        @ConditionalOnMissingBean(TokenToUserDetailsMapper.class)
        public TokenToUserDetailsMapper<UserDetails> tokenToUserDetailsMapper() {
            return new DefaultTokenToUserDetailsMapper();
        }

        /**
         * Token writer bean.
         */
        @Bean
        @Order(Ordered.LOWEST_PRECEDENCE - 1)
        @ConditionalOnMissingBean(CookieTokenWriter.class)
        @ConditionalOnProperty(value = "security.jwt.cookie-token-writer.enabled", matchIfMissing = true)
        public TokenWriter cookieTokenWriter() {
            return new CookieTokenWriter();
        }

        /**
         * Token writer bean.
         */
        @Bean
        @Order(Ordered.LOWEST_PRECEDENCE)
        @ConditionalOnMissingBean(PayloadTokenWriter.class)
        @ConditionalOnProperty(value = "security.jwt.payload-token-writer.enabled", matchIfMissing = true)
        public TokenWriter payloadTokenWriter() {
            return new PayloadTokenWriter();
        }

        /**
         * Token readers bean.
         */
        @Bean
        @Order(Ordered.LOWEST_PRECEDENCE - 1)
        @ConditionalOnMissingBean(HeaderTokenReader.class)
        @ConditionalOnProperty(value = "security.jwt.header-token-finder.enabled", matchIfMissing = true)
        public HeaderTokenReader headerTokenReader() {
            return new HeaderTokenReader();
        }

        @Bean
        @Order(Ordered.LOWEST_PRECEDENCE)
        @ConditionalOnMissingBean(CookieTokenReader.class)
        @ConditionalOnProperty(value = "security.jwt.cookie-token-finder.enabled", matchIfMissing = true)
        public CookieTokenReader cookieTokenReader() {
            return new CookieTokenReader();
        }

    }

}
