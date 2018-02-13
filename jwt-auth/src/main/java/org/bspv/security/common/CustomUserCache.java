/**
 *
 */
package org.bspv.security.common;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties.User;
import org.springframework.cache.Cache;
import org.springframework.cache.Cache.ValueWrapper;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import lombok.extern.slf4j.Slf4j;

/**
 * User cache implementation to handle {@link User}.
 */
@Slf4j
public class CustomUserCache implements UserCache, InitializingBean {

    /**
     * Name of the users cache.
     */
    public static final String USER_CACHE_NAME = "users";

    /**
     * Spring cache.
     */
    private final Cache cache;

    /**
     * Default constructor.
     */
    public CustomUserCache(final Cache cache) {
        this.cache = cache;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
     */
    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.cache, "cache mandatory");
    }

    /*
     * (non-Javadoc)
     *
     * @see org.springframework.security.core.userdetails.UserCache#getUserFromCache(java.lang.String)
     */
    @Override
    public UserDetails getUserFromCache(final String username) {
        final ValueWrapper element = this.cache.get(username.toLowerCase());
        if (log.isDebugEnabled()) {
            log.debug("Cache hit: {0} ; username: {1}", (element != null), username.toLowerCase());
        }
        return (element == null) ? null : (UserDetails) element.get();
    }

    /*
     * (non-Javadoc)
     *
     * @see org.springframework.security.core.userdetails.UserCache#putUserInCache(org.springframework.security.core.
     * userdetails.UserDetails)
     */
    @Override
    public void putUserInCache(final UserDetails user) {
        if (log.isDebugEnabled()) {
            log.debug("Cache put: {}", user.getUsername().toLowerCase());
        }
        this.cache.put(user.getUsername().toLowerCase(), user);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.springframework.security.core.userdetails.UserCache#removeUserFromCache(java.lang.String)
     */
    @Override
    public void removeUserFromCache(final String username) {
        if (log.isDebugEnabled()) {
            log.debug("Cache remove: {}", username.toLowerCase());
        }
        this.cache.evict(username.toLowerCase());
    }

}
