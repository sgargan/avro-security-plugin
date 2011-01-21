package com.sprocketry.avro.security;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.SecurityManager;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * <code>ShiroAuthenticationStrategyTest</code>
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration("/avro-shiro-security-context.xml")
public class ShiroAuthenticationStrategyTest extends AbstractAuthenticationStrategyTest {

	@Autowired
	private SecurityManager securityManager;

	@Before
	public void setupSecurityManager() throws Exception {
		SecurityUtils.setSecurityManager(securityManager);
	}
}
