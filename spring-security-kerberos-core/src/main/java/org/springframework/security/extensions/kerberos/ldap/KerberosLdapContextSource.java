package org.springframework.security.extensions.kerberos.ldap;

import java.security.PrivilegedAction;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.util.Assert;

/** Implementation of a {@link LdapContextSource} that authenticates against the ldap server using
 *  Kerberos.
 * 
 * @author nrodrigues
 *
 */
public class KerberosLdapContextSource extends DefaultSpringSecurityContextSource implements InitializingBean {

	private Configuration loginConfig;

	public KerberosLdapContextSource(String url) {
		super(url);
	}

	public KerberosLdapContextSource(List<String> urls, String baseDn) {
		super(urls, baseDn);
	}

	/**
	 * The login configuration for getting the serviceSubject from LoginContext
	 * 
	 * @param loginConfig
	 */
	public void setLoginConfig(Configuration loginConfig) {
		this.loginConfig = loginConfig;
	}

	
	@Override
	public void afterPropertiesSet() throws Exception {
		super.afterPropertiesSet();

		Assert.notNull(this.loginConfig, "loginConfig must be specified");
	}
	
	private Subject login() {
		try {
			LoginContext lc = new LoginContext(KerberosLdapContextSource.class.getSimpleName(), null, null, this.loginConfig);
			
			lc.login();
			
			return lc.getSubject();
		} catch (LoginException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	@SuppressWarnings("unchecked")
	protected DirContext getDirContextInstance(final @SuppressWarnings("rawtypes") Hashtable environment) throws NamingException {
		environment.put(Context.SECURITY_AUTHENTICATION, "GSSAPI");
		
		Subject serviceSubject = login();

		return Subject.doAs(serviceSubject, new PrivilegedAction<DirContext>() {

			@Override
			public DirContext run() {
				try {
					return KerberosLdapContextSource.super.getDirContextInstance(environment);
				} catch (NamingException e) {
					throw new RuntimeException(e);
				}
			}
		});
	}

}
