package com.sprocketry.avro.security;

import org.apache.avro.Protocol.Message;
import org.apache.avro.security.Ticket;

/**
 * <code>AuthenticationStrategy</code>
 */
public interface AuthenticationStrategy {

    /**
     * Verify the given credentials
     *
     * @param username the identity of the principal to be verified
     * @param password principal's password, possibly encoded
     * @param message the message being invoked
     */
    Ticket authenticate(CharSequence username, CharSequence password, Message message);

    Ticket verifyTicket(Ticket ticket, Message message);

}
