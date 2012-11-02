/*
 * Copyright 2009 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.extensions.kerberos;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.Assert;

/**
 * Implementation of {@link KerberosTicketValidator} which uses the SUN JAAS
 * login module, which is included in the SUN JRE, it will not work with an IBM
 * JRE. The whole configuration is done in this class, no additional JAAS
 * configuration is needed.
 * 
 * @author Mike Wiesner
 * @since 1.0
 * @version $Id$
 */
public class DefaultKerberosTicketValidator implements KerberosTicketValidator, InitializingBean {
	private Subject serviceSubject;

	private Configuration loginConfig;

	/**
	 * The login configuration for getting the serviceSubject from LoginContext
	 * 
	 * @param loginConfig
	 */
	public void setLoginConfig(Configuration loginConfig) {
		this.loginConfig = loginConfig;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
	 */
	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.loginConfig, "loginConfig must be specified");

		LoginContext lc = new LoginContext(DefaultKerberosTicketValidator.class.getSimpleName(), null, null, this.loginConfig);
		lc.login();

		this.serviceSubject = lc.getSubject();
	}
	
	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.springframework.security.extensions.kerberos.KerberosTicketValidator
	 * #validateTicket(byte[])
	 */
	public String validateTicket(byte[] token) {
		String username = null;
		try {
			username = Subject.doAs(this.serviceSubject, new KerberosValidateAction(token));
		} catch (PrivilegedActionException e) {
			throw new BadCredentialsException("Kerberos validation not succesfull", e);
		}
		return username;
	}

	/**
	 * This class is needed, because the validation must run with previously
	 * generated JAAS subject which belongs to the service principal and was
	 * loaded out of the keytab during startup.
	 * 
	 * @author Mike Wiesner
	 * @since 1.0
	 */
	private static class KerberosValidateAction implements PrivilegedExceptionAction<String> {
		byte[] kerberosTicket;

		public KerberosValidateAction(byte[] kerberosTicket) {
			this.kerberosTicket = kerberosTicket;
		}

		@Override
		public String run() throws Exception {
			GSSContext context = GSSManager.getInstance().createContext((GSSCredential) null);
			context.acceptSecContext(kerberosTicket, 0, kerberosTicket.length);
			
			String user = context.getSrcName().toString();
			context.dispose();
			
			return user;
		}

	}

}
