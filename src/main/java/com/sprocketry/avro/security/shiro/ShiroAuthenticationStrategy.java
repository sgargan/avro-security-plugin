package com.sprocketry.avro.security.shiro;

import org.apache.avro.Protocol.Message;
import org.apache.avro.security.Ticket;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;

import com.sprocketry.avro.security.AuthenticationStrategy;

/**
 * <code>ShiroAuthenticationStrategy</code> hooks into the Apache Shiro Security
 * framework http://shiro.apache.org
 * 
 * Shiro provides its own caching at the realm level so this implementation
 * defers to that caching and uses no Ticketing.
 */
public class ShiroAuthenticationStrategy implements AuthenticationStrategy {

    @Override
    public Ticket authenticate(CharSequence username, CharSequence password, Message message) {

        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username.toString(),
                password.toString());
        token.setRememberMe(true);
        subject.login(token);

        return null;
    }

    @Override
    public Ticket verifyTicket(Ticket ticket, Message message) {
        return null;
    }
}
