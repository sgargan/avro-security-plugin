package com.sprocketry.avro.security;

import org.apache.avro.ipc.AvroRemoteException;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.security.access.prepost.PreAuthorize;

public class MockFoo implements Foo { 

    @PreAuthorize("hasRole('ROLE_USER')")
    @RequiresRoles(value = { "user" })
    public int foo(Bar bar) throws AvroRemoteException {
        return 12345;
    }
}