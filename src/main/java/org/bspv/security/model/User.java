/**
 * 
 */
package org.bspv.security.model;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;

/**
 * Represents a user of this service.
 * This class is not immutable as the {@link CredentialsContainer} interface should let the password/key to be erased.
 */
@ToString
@EqualsAndHashCode(of = { "username" })
public final class User implements Serializable, UserDetails, CredentialsContainer, Cloneable {

    /**
     * Generated serial version UID.
     */
    private static final long serialVersionUID = 3180450620024125623L;

    /**
     * Builder class for {@link User}.
     * 
     */
    public static class Builder {

        /** @see User#id */
        private UUID id;
        /** @see User#version */
        private Long version;
        /** @see User#username */
        private String username;
        /** @see User#password */
        private String password;
        /** @see User#enabled */
        private boolean enabled = true;
        /** @see User#email */
        private String email;
        /** @see User#authorities */
        
        private Set<ServiceGrantedAuthority> authorities = new HashSet<>();

        /**
         * Constructor of the builder.
         * 
         */
        private Builder() {
            super();
        }

        /**
         * build the user calling the constructor or the User class.
         * 
         * @return new instance of {@link User}
         */
        public User build() {
            return new User(this);
        }

        /**
         * 
         * @param id
         * @return this builder instance
         */
        public Builder id(UUID id) {
            this.id = id;
            return this;
        }

        /**
         * 
         * @param version
         * @return this builder instance
         */
        public Builder version(Long version) {
            this.version = version;
            return this;
        }

        /**
         * 
         * @param userName
         * @return this builder instance
         */
        public Builder username(@NonNull String userName) {
            this.username = userName;
            return this;
        }

        /**
         * @param email
         * @return this builder instance
         */
        public Builder email(String email) {
            this.email = email;
            return this;
        }

        /**
         * @param key
         * @return this builder instance
         */
        public Builder password(@NonNull String password) {
            this.password = password;
            return this;
        }

        /**
         * @param enabled
         * @return this builder instance
         */
        public Builder enable(boolean enabled) {
            this.enabled = enabled;
            return this;
        }

        /**
         * @param authority
         * @return this builder instance
         */
        public Builder authority(ServiceGrantedAuthority authority) {
            this.authorities.add(authority);
            return this;
        }

        /**
         * @param authorities
         * @return this builder instance
         */
        public Builder authorities(Collection<ServiceGrantedAuthority> authorities) {
            this.authorities.addAll(authorities);
            return this;
        }

    }

    /**
     * Unique identifier of the user.
     */
    @Getter
    private final UUID id;

    /**
     * Version of the bean
     */
    @Getter
    private final Long version;

    /**
     * Unique userName.
     */
    @Getter
    private final String username;

    /**
     * User key.
     */
    private String password;

    /**
     * Flag indicating if the user is enabled.
     */
    @Getter
    private final boolean enabled;

    /**
     * User's email.
     */
    @Getter
    private final String email;

    /**
     * Set of {@link ServiceGrantedAuthority}s.
     */
    @Getter
    private final Set<ServiceGrantedAuthority> authorities = new HashSet<>();
    

    /**
     * Static method to access the builder.
     * 
     * @return a new {@link Builder} instance.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Constructor. Builder pattern.
     * 
     * @param builder
     */
    private User(Builder builder) {
        this.id = builder.id != null ? builder.id : UUID.randomUUID();
        this.version = builder.version != null ? builder.version : 0L;
        this.username = builder.username;
        this.password = builder.password;
        this.enabled = builder.enabled;
        this.email = builder.email;
        this.authorities.addAll(builder.authorities);
    }

    public Builder toBuilder() {
        Builder builder = User.builder();
        builder.id = this.id;
        builder.version = this.version;
        builder.username = this.username;
        builder.password = this.password;
        builder.enabled = this.enabled;
        builder.email = this.email;
        builder.authorities.addAll(this.authorities);
        return builder;
    }
    
    /*
     * (non-Javadoc)
     * @see org.springframework.security.core.CredentialsContainer#eraseCredentials()
     */
    @Override
    public void eraseCredentials() {
        this.password = null;
    }
    
    /**
     * Just to be used with the stream API.
     * @return
     */
    public User clearCredentials() {
        this.eraseCredentials();
        return this;
    }

    /*
     * (non-Javadoc)
     * @see org.springframework.security.core.userdetails.UserDetails#getPassword()
     */
    @Override
    public String getPassword() {
        return this.password;
    }

    /*
     * (non-Javadoc)
     * @see org.springframework.security.core.userdetails.UserDetails#isAccountNonExpired()
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /*
     * (non-Javadoc)
     * @see org.springframework.security.core.userdetails.UserDetails#isAccountNonLocked()
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /*
     * (non-Javadoc)
     * @see org.springframework.security.core.userdetails.UserDetails#isCredentialsNonExpired()
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public User clone() throws CloneNotSupportedException {
        return this.toBuilder().build();
    }
    
    
}
