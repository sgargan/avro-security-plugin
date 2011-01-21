package com.sprocketry.avro.security;

import static org.junit.Assert.assertEquals;

import org.apache.avro.AvroRuntimeException;
import org.apache.avro.ipc.LocalTransceiver;
import org.apache.avro.specific.SpecificRequestor;
import org.apache.avro.specific.SpecificResponder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.test.annotation.ExpectedException;

public abstract class AbstractAuthenticationStrategyTest {

    @Autowired
    @Qualifier("testService")
    protected MockFoo testImpl;

    @Autowired
    protected AuthenticationPlugin serverPlugin;

    protected AuthenticationPlugin clientPlugin;

    protected Foo client;

    public AbstractAuthenticationStrategyTest() {
        super();
    }

    @Test
    public void validcredentials() throws Exception {
        for (int x = 0; x < 5; x++)
            assertEquals(12345, client.foo(new Bar()));
    }

    @Test
    @ExpectedException(AvroRuntimeException.class)
    public void invalidCredentials() throws Exception {
        clientPlugin.setPassword("notcorrect");
        assertEquals(12345, client.foo(new Bar()));
    }

    @Test
    @ExpectedException(AvroRuntimeException.class)
    public void invalidAuthorizationForCall() throws Exception {
        clientPlugin.setUsername("billy");
        clientPlugin.setPassword("hasNoRoles");
        assertEquals(12345, client.foo(new Bar()));
    }

    @Before
    public void testSecurityContext() throws Exception {
        SpecificResponder responder = new SpecificResponder(Foo.class, testImpl);
        responder.addRPCPlugin(serverPlugin);

        clientPlugin = new AuthenticationPlugin();
        clientPlugin.setUsername("rredford");
        clientPlugin.setPassword("afghanistanbananastand");
        SpecificRequestor testRequestor = new SpecificRequestor(Foo.class, new LocalTransceiver(
                responder));
        testRequestor.addRPCPlugin(clientPlugin);

        client = SpecificRequestor.getClient(Foo.class, testRequestor);
    }

}