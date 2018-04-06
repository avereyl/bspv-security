package org.bspv.security.model;

import org.springframework.security.core.GrantedAuthority;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;

@ToString
@EqualsAndHashCode(of = { "service", "grantedAuthority" })
public final class ServiceGrantedAuthority implements GrantedAuthority {
    
    /**
     * 
     */
    private static final long serialVersionUID = -174852487691118047L;
    
    /**
     * Builder class for {@link ServiceGrantedAuthority}.
     * 
     */
    public static class Builder {
         /** @see ServiceGrantedAuthority#service */
        private String service;
        /** @see ServiceGrantedAuthority#grantedAuthority */
        private GrantedAuthority grantedAuthority;
        
        public Builder service(@NonNull String service) {
            this.service = service;
            return this;
        }
        
        public Builder grantedAuthority(@NonNull GrantedAuthority grantedAuthority) {
            this.grantedAuthority = grantedAuthority;
            return this;
        }
        
        public ServiceGrantedAuthority build() {
            return new ServiceGrantedAuthority(this);
        }
        
        
    }
    
    @Getter
    private final String service;
    
    @Getter
    private final GrantedAuthority grantedAuthority;
    
    public ServiceGrantedAuthority(String service, GrantedAuthority grantedAuthority) {
        super();
        this.service = service;
        this.grantedAuthority = grantedAuthority;
    }
    /**
     * Constructor. Builder pattern.
     * 
     * @param builder
     */
    private ServiceGrantedAuthority(Builder builder) {
        this.service = builder.service != null ? builder.service : "";
        this.grantedAuthority = builder.grantedAuthority;
    }
    
    /**
     * Static method to access the builder.
     * 
     * @return a new {@link Builder} instance.
     */
    public static Builder builder() {
        return new Builder();
    }

    /*
     * (non-Javadoc)
     * @see org.springframework.security.core.GrantedAuthority#getAuthority()
     */
    @Override
    public String getAuthority() {
        return grantedAuthority.getAuthority();
    }


    

}
