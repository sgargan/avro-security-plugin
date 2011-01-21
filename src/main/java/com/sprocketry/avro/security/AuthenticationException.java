package com.sprocketry.avro.security;

/**
 * <code>AuthenticationException</code>
 */
public class AuthenticationException extends RuntimeException{

    public AuthenticationException(String message){
        super(message);
    }

    public AuthenticationException(Throwable t){
        super(t);
    }
}
