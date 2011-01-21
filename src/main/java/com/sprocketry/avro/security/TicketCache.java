package com.sprocketry.avro.security;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.PriorityBlockingQueue;

import org.apache.avro.security.Ticket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;

/**
 * <code>TicketCache</code> is used to store currently valid
 * {@link Authentication}s for Users so that the overhead of Authentication and
 * Authorization can be avoided across multiple invocations.
 */
public class TicketCache<AuthType> {

    private Logger log = LoggerFactory.getLogger(getClass());

    private Map<Ticket, AuthHolder<AuthType>> ticketCache = new ConcurrentHashMap<Ticket, AuthHolder<AuthType>>();

    private Map<String, Ticket> ticketsByUser = new ConcurrentHashMap<String, Ticket>();

    private long expiry = 1000 * 60 * 60 * 24;

    private PriorityBlockingQueue<Ticket> expiryQueue = new PriorityBlockingQueue<Ticket>(100,
            new TicketComparator());

    public TicketCache() {
        ExpiredTicketReaper reaperThread = new ExpiredTicketReaper();
        reaperThread.start();
    }

    public TicketCache(int expiry) {
        this();
        this.expiry = expiry;
    }

    /**
     * Create a ticket and cache the given credentials and an arbitrary
     * authentication object for retrieval with the ticket.
     * 
     * @param username the principals username.
     * @param password the principals password
     * @param auth the authentication object that should be cached for the
     *            ticket
     * 
     * @return the ticket for the authentication.
     */
    public Ticket createTicket(String username, String password, AuthType auth) {
        Ticket ticket = buildTicket(username, password, System.currentTimeMillis() + expiry);
        ticketCache.put(ticket, new AuthHolder<AuthType>(username, auth));
        ticketsByUser.put(username, ticket);
        expiryQueue.add(ticket);
        return ticket;
    }

    /**
     * Cancel a ticket, removing it and its associated authentication data from
     * the cache.
     * 
     * @param ticket the ticket that is to be cancelled.
     */
    public void cancelTicket(Ticket ticket) {
        if (ticket != null) {
            AuthHolder<AuthType> auth = ticketCache.remove(ticket);
            if (auth != null) {
                ticketsByUser.remove(auth.username);
            }
        }
    }

    /**
     * Remove any ticket currently held for a username and thus force them to
     * re-authenticate.
     * 
     * @param username the username who's current tickets should be cancelled.
     */
    public void cancelTicketsForUsername(String username) {
        cancelTicket(ticketsByUser.get(username));
    }

    /**
     * Get the Authentication cached with the given ticket if one exists.
     * 
     * @param ticket
     * @return
     */
    public AuthType getAuthentication(Ticket ticket) {
        AuthHolder<AuthType> holder = ticketCache.get(ticket);
        if (holder != null) {
            return holder.type;
        }
        return null;
    }

    /**
     * The timeout in milliseconds after which the ticket will expire.
     * 
     * @param expiry
     */
    public void setTicketExpiry(long expiry) {
        this.expiry = expiry;
    }

    private Ticket buildTicket(CharSequence username, CharSequence password, long expiry) {

        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("No MD5 algorithm available!");
        }

        Ticket ticket = new Ticket();
        ticket.digest = ByteBuffer.wrap(digest.digest((username + ":" + password + expiry)
                .getBytes()));
        ticket.expiry = expiry;
        return ticket;
    }

    private class TicketComparator implements Comparator<Ticket> {
        public int compare(Ticket ticket1, Ticket ticket2) {
            if (ticket1.expiry > ticket2.expiry) {
                return -1;
            } else if (ticket1.expiry < ticket2.expiry) {
                return 1;
            } else {
                return 0;
            }
        }
    }

    /**
     * Allow injection of a cache map. For use in distributed caching of
     * tickets.
     * 
     * @param ticketCache
     */
    public void setTicketCacheMap(Map<Ticket, AuthHolder<AuthType>> ticketCache) {
        this.ticketCache = ticketCache;
    }

    /**
     * Allow injection of a user cache map. For use in distributed caching.
     * 
     * @param ticketCache
     */
    public void setTicketsByUser(Map<String, Ticket> ticketsByUser) {
        this.ticketsByUser = ticketsByUser;
    }

    private class ExpiredTicketReaper extends Thread {

        public ExpiredTicketReaper() {
            setPriority(Thread.MIN_PRIORITY);
            setName("Expired Authentication Ticket Reaper");
        }

        @Override
        public void run() {
            while (true) {
                Ticket current = null;
                try {
                    current = expiryQueue.take();
                    long delay = current.expiry - System.currentTimeMillis();
                    if (delay > 50) {
                        sleep(delay);
                    }
                    if (log.isDebugEnabled()) {
                        AuthHolder<AuthType> auth = ticketCache.remove(current);
                        if (auth != null) {
                            log.debug(
                                    "Authentication ticket for user '{}' has expired and will be removed",
                                    auth.username);
                        }
                        if (auth != null) {
                            ticketsByUser.remove(auth.username);
                        }
                    }
                } catch (InterruptedException e) {
                    expiryQueue.add(current);
                }
            }
        }
    }

    public static class AuthHolder<AuthType> {
        AuthType type;

        AuthHolder(String username, AuthType type) {
            this.username = username;
            this.type = type;
        }

        String username;

    }
}