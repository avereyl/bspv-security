package org.bspv.security.expressionhandler;

import java.util.UUID;

import org.bspv.security.model.User;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;

/**
 *@see  org.springframework.security.access.expression.method.MethodSecurityExpressionRoot
 * @author guillaume
 *
 */
public class CustomMethodSecurityExpressionRoot extends SecurityExpressionRoot
        implements MethodSecurityExpressionOperations {
    
    protected Object filterObject;
    protected Object returnObject;
    protected Object target;
    protected final String serviceName;

    public CustomMethodSecurityExpressionRoot(Authentication authentication, String serviceName) {
        super(authentication);
        this.serviceName = serviceName;
    }
    
    public boolean isAdmin() {
        return ((User) this.getPrincipal())
                .getAuthorities()
                .stream()
                .anyMatch( a -> this.serviceName.equals(a.getService()) 
                        && "ADMIN".equalsIgnoreCase(a.getAuthority()));
    }
    
    public boolean isMyself(UUID uuid) {
       return ((User) this.getPrincipal()).getId().equals(uuid);
    }
    
    /**
     * @return the filterObject
     */
    public Object getFilterObject() {
        return filterObject;
    }

    /**
     * @param filterObject the filterObject to set
     */
    public void setFilterObject(Object filterObject) {
        this.filterObject = filterObject;
    }

    /**
     * @return the returnObject
     */
    public Object getReturnObject() {
        return returnObject;
    }

    /**
     * @param returnObject the returnObject to set
     */
    public void setReturnObject(Object returnObject) {
        this.returnObject = returnObject;
    }

    /**
     * @return the target
     */
    public Object getTarget() {
        return target;
    }

    /**
     * Sets the "this" property for use in expressions. Typically this will be the "this"
     * property of the {@code JoinPoint} representing the method invocation which is being
     * protected.
     *
     * @param target the target object on which the method in is being invoked.
     */
    public void setTarget(Object target) {
        this.target = target;
    }

    @Override
    public Object getThis() {
        return this;
    }

}
