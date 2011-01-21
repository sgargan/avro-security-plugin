package com.sprocketry.avro.security;

/**
 * <code>AuthenticationException</code> is thrown by the plugin framework if there is any problems
 * Authenticating the user.
 */
public class AuthenticationException extends RuntimeException {

	public AuthenticationException(String message) {
		super(message);
	}

	public AuthenticationException(Throwable t) {
		super(t);
	}
}
