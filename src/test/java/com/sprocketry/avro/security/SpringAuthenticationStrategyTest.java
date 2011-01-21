package com.sprocketry.avro.security;

import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * <code>SpringAuthenticationStrategyTest</code>
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration("/avro-spring-security-context.xml")
public class SpringAuthenticationStrategyTest extends AbstractAuthenticationStrategyTest {
}
