package org.springframework.security.extensions.kerberos.ntlm;

import org.springframework.security.core.AuthenticationException;

public class NtlmException extends AuthenticationException {

	private static final long serialVersionUID = 1L;

	public NtlmException() {
		super("Ntlm Exception");
	}

	public NtlmException(String message, Throwable cause) {
		super(message, cause);
	}

	public NtlmException(String message) {
		super(message);
	}
}
