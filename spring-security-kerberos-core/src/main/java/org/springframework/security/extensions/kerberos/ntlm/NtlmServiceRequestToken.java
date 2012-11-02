package org.springframework.security.extensions.kerberos.ntlm;

import org.springframework.security.authentication.AbstractAuthenticationToken;

public class NtlmServiceRequestToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 1L;
	
	private final byte[] token;

	public NtlmServiceRequestToken(byte[] token) {
		super(null);
		this.token = token;
	}
	
	public byte[] getToken() {
		return token;
	}
	
	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getPrincipal() {
		return null;
	}


}
