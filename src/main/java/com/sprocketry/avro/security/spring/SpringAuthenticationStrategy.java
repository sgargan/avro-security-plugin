package com.sprocketry.avro.security.spring;

import org.apache.avro.Protocol.Message;
import org.apache.avro.security.Ticket;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import com.sprocketry.avro.security.AuthenticationException;
import com.sprocketry.avro.security.AuthenticationStrategy;
import com.sprocketry.avro.security.TicketCache;

/**
 * <code>SpringAuthenticationStrategy</code> uses Spring's Security framework to
 * authenticate the user and authorize the request avro operation.
 */
public class SpringAuthenticationStrategy implements AuthenticationStrategy {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userService;

    @Autowired
    private TicketCache<UsernamePasswordAuthenticationToken> ticketCache;

    @Override
    public Ticket authenticate(CharSequence username, CharSequence password, Message message) {

        username = username.toString();
        password = password.toString();
        UserDetails details = userService.loadUserByUsername(username.toString());
        Ticket ticket = new Ticket();
        if (details != null) {
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    username, password, details.getAuthorities());
            auth.setDetails(details);

            auth = (UsernamePasswordAuthenticationToken) authenticationManager.authenticate(auth);
            if (auth != null) {
                SecurityContextHolder.getContext().setAuthentication(auth);
                ticket = ticketCache.createTicket((String) username, (String) password, auth);
            }
        } else {
            throw new AuthenticationException("Error authenticating user '" + username + "'");
        }
        return ticket;
    }

    @Override
    public Ticket verifyTicket(Ticket ticket, Message message) {

        if (ticket != null) {
            Authentication auth = ticketCache.getAuthentication(ticket);
            if (auth != null) {
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }
        return ticket;
    }
}
