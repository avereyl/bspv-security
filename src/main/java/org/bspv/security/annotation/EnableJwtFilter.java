package org.bspv.security.annotation;

import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import org.bspv.security.config.JwtFilterConfiguration;
import org.springframework.context.annotation.Import;

@Retention(RUNTIME)
@Target(TYPE)
@Import(JwtFilterConfiguration.class)
public @interface EnableJwtFilter {
}
