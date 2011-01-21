package com.sprocketry.avro.security;

import org.apache.avro.AvroRuntimeException;
import org.apache.avro.io.BinaryDecoder;
import org.apache.avro.io.BinaryEncoder;
import org.apache.avro.io.DecoderFactory;
import org.apache.avro.ipc.RPCContext;
import org.apache.avro.ipc.RPCPlugin;
import org.apache.avro.security.Authentication;
import org.apache.avro.security.Credentials;
import org.apache.avro.security.Ticket;
import org.apache.avro.specific.SpecificDatumReader;
import org.apache.avro.specific.SpecificDatumWriter;
import org.apache.avro.util.Utf8;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.codec.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Map;

import static java.lang.String.format;

/**
 * <code>AuthenticationPlugin</code> uses Avro's plugin & IPC metadata
 * mechanisms to Authenticate and Authorize IPC communications. An instance of
 * the plugin should be added to both the
 * <p/>
 * {@linkRequestor) and {@linkResponder). When a request is initiated, the
 * plugin on the Requestor side encodes the principals credentials into the
 * request call metadata.
 * <p/>
 * The Responder reads the encoded credentials and provides them to a supplied
 * @link(AuthenticationStrategy) for authentication and authorization. If the
 * credentials are valid, the strategy returns a ticket to the server which is
 * encoded into the response. The ticket can then be used by the client in
 * future requests to avoid the verification overhead.
 */
public class AuthenticationPlugin extends RPCPlugin {

    private static Utf8 AuthenticationKey = new Utf8("security.credentials");

    private Logger log = LoggerFactory.getLogger(getClass());

    private SpecificDatumReader<Authentication> authenticationReader = new SpecificDatumReader<Authentication>(
            Authentication.class);

    private SpecificDatumWriter<Authentication> authenticationWriter = new SpecificDatumWriter<Authentication>(
            Authentication.class);

    private AuthenticationStrategy strategy;

    private ThreadLocal<Object> ticketStorage = new ThreadLocal<Object>();

    private Utf8 username;

    private Utf8 password;

    private final Ticket NO_TICKET ;
    
    public AuthenticationPlugin() {
        NO_TICKET = new Ticket();
        NO_TICKET.digest = ByteBuffer.allocate(0);        
    }

    /**
     * Set the username to be used in authenticating the request
     * 
     * @param username
     */
    public void setUsername(String username) {
        this.username = new Utf8(username);
    }

    /**
     * Set the password to be used in authenticating the request
     * 
     * @param password
     */
    public void setPassword(String password) throws Exception {
        if (password != null) {
            this.password = new Utf8(password);
        }
    }

    /**
     * Called on the client after the initial RPC handshake
     * 
     * @param context the handshake rpc context
     */
    public void clientSendRequest(RPCContext context) {

        try {
            Authentication auth = new Authentication();
            Ticket ticket = (Ticket) ticketStorage.get();
            if (ticket == null) {
                Credentials credentials = new Credentials();
                assertCredentialsArePresent();
                credentials.username = username;
                credentials.password = password;
                logCredentials(credentials);
                auth.data = credentials;
            } else {
                logTicket(ticket);
                auth.data = ticket;
            }
            writeAuthenticationToMetadata(context.requestCallMeta(), auth);
        } catch (IOException e) {
            log.error("Error decoding credentials from request.", e);
        }
    }

    private void assertCredentialsArePresent() {
        if (username == null) {
            throw new AuthenticationException(
                    "No username has been supplied to the Authentication plugin");
        }
        if (password == null) {
            throw new AuthenticationException(
                    "No password has been supplied to the Authentication plugin");
        }
    }

    private void writeAuthenticationToMetadata(Map<CharSequence, ByteBuffer> metadata,
            Authentication auth) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        BinaryEncoder encoder = new BinaryEncoder(out);
        authenticationWriter.write(auth, encoder);
        metadata.put(AuthenticationKey, ByteBuffer.wrap(out.toByteArray()));
    }

    /**
     * This method is invoked at the RPC server when the request is received,
     * but before the call itself is executed
     * 
     * @param context the per-call rpc context (in/out parameter)
     */
    public void serverReceiveRequest(RPCContext context) {

        Authentication response = readAuthenticationFromMetadata(context.requestCallMeta());

        if (strategy != null) {
            if (response.data instanceof Ticket) {
                Ticket ticket = (Ticket) response.data;
                logTicket(ticket);
                strategy.verifyTicket(ticket, context.getMessage());
            } else if (response.data instanceof Credentials) {
                Credentials credentials = (Credentials) response.data;
                logCredentials(credentials);
                Ticket ticket = null;
                ticket = strategy.authenticate(credentials.username, credentials.password,
                        context.getMessage());
                if (ticket != null) {
                    logTicket(ticket);
                    ticketStorage.set(ticket);
                } else {
                    ticket = NO_TICKET;
                }                
            } else {
                throw new AuthenticationException("No Credentials or ticket in Authentication.");
            }
        } else {
            throw new AuthenticationException("No Authentication strategy has been supplied.");
        }
    }

    /**
     * This method is invoked at the client after the call is executed, and
     * after the client receives the response
     * 
     * @param context the per-call rpc context
     */
    public void clientReceiveResponse(RPCContext context) {
        Authentication auth = readAuthenticationFromMetadata(context.responseCallMeta());
        if (!NO_TICKET.equals(auth.data)) {
            ticketStorage.set(auth.data);
        }
    }

    /**
     * This method is invoked at the server before the response is executed, but
     * before the response has been formulated
     * 
     * @param context the per-call rpc context (in/out parameter)
     */
    public void serverSendResponse(RPCContext context) {
        Authentication auth = new Authentication();
        auth.data = ticketStorage.get();
        if (auth.data == null) {
            auth.data = NO_TICKET;
        }
        try {
            writeAuthenticationToMetadata(context.responseCallMeta(), auth);
        } catch (IOException e) {
            log.error("Error writing authentication to response metadata", e);
        }
    }

    private Authentication readAuthenticationFromMetadata(Map<CharSequence, ByteBuffer> metadata) {
        ByteBuffer buffer = metadata.get(AuthenticationKey);
        if (buffer == null) {
            throw new AvroRuntimeException(
                    "No Authentication metadata present. "
                            + "Insure the Security plugin has been included in both requestor and responder");
        }
        BinaryDecoder decoder = DecoderFactory.defaultFactory().createBinaryDecoder(
                new ByteBufferBackedInputStream(buffer), null);

        Authentication auth = null;
        try {
            auth = authenticationReader.read(null, decoder);
        } catch (Exception e) {
            log.error("Error decoding credentials for transfer.", e);
        }
        return auth;
    }

    private void logCredentials(Credentials credentials) {
        if (log.isDebugEnabled()) {
            log.debug(format("Processing credentials for '%s' and '%s'", credentials.username,
                    credentials.password));
        }
    }

    private void logTicket(Ticket ticket) {
        if (log.isDebugEnabled()) {
            log.debug(format("Using security ticket '%s' ",
                    new String(Hex.encode(ticket.digest.array()))));
        }
    }

    public void setAuthenticationStrategy(AuthenticationStrategy strategy) {
        this.strategy = strategy;
    }

    private static class ByteBufferBackedInputStream extends InputStream {

        ByteBuffer buf;

        ByteBufferBackedInputStream(ByteBuffer buf) {
            this.buf = buf;
        }

        public synchronized int read() throws IOException {
            if (!buf.hasRemaining()) {
                return -1;
            }
            return buf.get();
        }

        public synchronized int read(byte[] bytes, int off, int len) throws IOException {
            len = Math.min(len, buf.remaining());
            if (len == 0) {
                return -1;
            }
            buf.get(bytes, off, len);
            return len;
        }
    }

    public static class ByteBufferBackedOutputStream extends OutputStream {
        ByteBuffer buf;

        ByteBufferBackedOutputStream(ByteBuffer buf) {
            this.buf = buf;
        }

        public synchronized void write(int b) throws IOException {
            buf.put((byte) b);
        }

        public synchronized void write(byte[] bytes, int off, int len) throws IOException {
            buf.put(bytes, off, len);
        }

    }
}
