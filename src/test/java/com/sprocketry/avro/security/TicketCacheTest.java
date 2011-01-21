package com.sprocketry.avro.security;

import static org.junit.Assert.assertEquals;

import org.apache.avro.security.Ticket;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

public class TicketCacheTest {

    private String username = "rredford";

    private String password = "afghanistanbananastand";

    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username,
            password);

    private TicketCache<Authentication> cache;

    @Test
    public void cacheAuthentication() {
        Ticket ticket = cache.createTicket(username, password, auth);
        assertEquals(auth, cache.getAuthentication(ticket));
    }

    @Test
    public void expiredTicketsAreRemoved() throws InterruptedException {
        Ticket ticket = cache.createTicket(username, password, auth);
        assertEquals(auth, cache.getAuthentication(ticket));
        Thread.sleep(1000);
        assertEquals(null, cache.getAuthentication(ticket));
    }

    @Test
    public void forceExpirationForUser() {
        Ticket ticket = cache.createTicket(username, password, auth);
        assertEquals(auth, cache.getAuthentication(ticket));
        cache.cancelTicketsForUsername(username);
        assertEquals(null, cache.getAuthentication(ticket));
    }

    @Before
    public void setup() {
        cache = new TicketCache<Authentication>(500);
        cache.setTicketExpiry(500);
    }
}
