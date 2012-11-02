package org.springframework.security.extensions.kerberos.ntlm;

import java.io.IOException;

import jcifs.Config;
import jcifs.ntlmssp.NtlmFlags;
import jcifs.ntlmssp.NtlmMessage;
import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbSession;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.Assert;

/**
 * User: gcermak Date: 3/15/11
 * <p/>
 */
public class NtlmAuthenticationProvider implements AuthenticationProvider, InitializingBean {
	protected String defaultDomain;

	private UserDetailsService userDetailsService;

	public NtlmAuthenticationProvider() {
		Config.setProperty("jcifs.smb.client.soTimeout", "1800000");
		Config.setProperty("jcifs.netbios.cachePolicy", "1200");
		Config.setProperty("jcifs.smb.lmCompatibility", "0");
		Config.setProperty("jcifs.smb.client.useExtendedSecurity", "true");
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		NtlmServiceRequestToken auth = (NtlmServiceRequestToken) authentication;
		byte[] token = auth.getToken();

		String username = null;
		String password = null;

		NtlmMessage message = constructNTLMMessage(token);

		if (message instanceof Type1Message) {
			Type2Message type2Message = new Type2Message((Type1Message) message, getChallenge(), null);
			type2Message.setFlag(NtlmFlags.NTLMSSP_NEGOTIATE_128, true);
			
			throw new NtlmType2MessageException(type2Message.toByteArray());
		}
		if (message instanceof Type3Message) {
			Type3Message type3Message = (Type3Message) message;

			final byte[] lmResponse = (type3Message.getLMResponse() != null) ? type3Message.getLMResponse() : new byte[0];
			final byte[] ntResponse = (type3Message.getNTResponse() != null) ? type3Message.getNTResponse() : new byte[0];

			NtlmPasswordAuthentication ntlmPasswordAuthentication = new NtlmPasswordAuthentication(type3Message.getDomain(), type3Message.getUser(),
					getChallenge(), lmResponse, ntResponse);

			username = ntlmPasswordAuthentication.getUsername();
			password = ntlmPasswordAuthentication.getPassword();
		}

		// do custom logic here to find the user ...
		UserDetails userDetails = userDetailsService.loadUserByUsername(username);

		return new UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());
	}

	// The Client will only ever send a Type1 or Type3 message ... try 'em both
	protected static NtlmMessage constructNTLMMessage(byte[] token) {
		NtlmMessage message = null;
		try {
			message = new Type1Message(token);
			return message;
		} catch (IOException e) {
			if ("Not an NTLMSSP message.".equals(e.getMessage())) {
				return null;
			}
		}

		try {
			message = new Type3Message(token);
			return message;
		} catch (IOException e) {
			if ("Not an NTLMSSP message.".equals(e.getMessage())) {
				return null;
			}
		}

		return message;
	}

	protected byte[] getChallenge() {
		try {
			return SmbSession.getChallengeForDomain().challenge;
		} catch (IOException e) {
			throw new NtlmException(e.getMessage(), e);
		}
	}

	@Override
	public boolean supports(Class<? extends Object> auth) {
		return NtlmServiceRequestToken.class.isAssignableFrom(auth);
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.hasText(defaultDomain, "defaultDomain must be specified");
		Assert.notNull(userDetailsService);
	}

	public void setSmbClientUsername(String smbClientUsername) {
		Config.setProperty("jcifs.smb.client.username", smbClientUsername);
	}

	public void setSmbClientPassword(String smbClientPassword) {
		Config.setProperty("jcifs.smb.client.password", smbClientPassword);
	}

	public void setDefaultDomain(String defaultDomain) {
		this.defaultDomain = defaultDomain;
		Config.setProperty("jcifs.smb.client.domain", defaultDomain);
	}

	/**
	 * 0: Nothing 1: Critical [default] 2: Basic info. (Can be logged under
	 * load) 3: Detailed info. (Highest recommended level for production use) 4:
	 * Individual smb messages 6: Hex dumps
	 * 
	 * @param logLevel
	 *            the desired logging level
	 */
	public void setDebugLevel(int logLevel) throws Exception {
		switch (logLevel) {
		case 0:
		case 1:
		case 2:
		case 3:
		case 4:
		case 6:
			Config.setProperty("jcifs.util.loglevel", Integer.toString(logLevel));
			break;
		default:
			throw new Exception("Invalid Log Level specified");
		}
	}

	/**
	 * 
	 * @param winsList
	 *            a comma separates list of wins addresses (ex.
	 *            10.169.10.77,10.169.10.66)
	 */
	public void setNetBiosWins(String winsList) {
		Config.setProperty("jcifs.netbios.wins", winsList);
	}

	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

}