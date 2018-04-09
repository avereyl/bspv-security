/**
 * 
 */
package org.bspv.security.expressionhandler;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;

/**
 * @author guillaume
 *
 */
public class CustomMethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

    protected String serviceName;
    
    protected AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    public CustomMethodSecurityExpressionHandler(String serviceName) {
        super();
        this.serviceName = serviceName;
    }

    @Override
    protected MethodSecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication,
            MethodInvocation invocation) {
        CustomMethodSecurityExpressionRoot root = new CustomMethodSecurityExpressionRoot(authentication, this.serviceName);
        root.setPermissionEvaluator(getPermissionEvaluator());
        root.setTrustResolver(this.trustResolver);
        root.setRoleHierarchy(getRoleHierarchy());
        return root;
    }

    /* (non-Javadoc)
     * @see org.springframework.security.access.expression.AbstractSecurityExpressionHandler#getPermissionEvaluator()
     */
    @Override
    public PermissionEvaluator getPermissionEvaluator() {
        return super.getPermissionEvaluator();
    }
    
    
}
