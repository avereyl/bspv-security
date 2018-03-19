package org.bspv.security.common;


import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.apache.commons.lang3.SerializationUtils;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public final class InMemoryReadOnlyUserDetailsService implements UserDetailsService {

    private final Map<String, UserDetails> users = new HashMap<String, UserDetails>();

    public  InMemoryReadOnlyUserDetailsService(Collection<? extends UserDetails> users) {
        super();
        users.stream().forEach(u -> {
            if (!this.users.containsKey(u.getUsername())) {
                this.users.put(u.getUsername(), u);
            } else {
                log.warn("User {} already exists, ignored. Please check your config.", u.getUsername());
            }
        });

    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.core.userdetails.UserDetailsService#
     * loadUserByUsername(java.lang.String)
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails user = users.get(username.toLowerCase());
        if (user == null) {
            throw new UsernameNotFoundException(username);
        }
        return SerializationUtils.clone(user);
    }

}
