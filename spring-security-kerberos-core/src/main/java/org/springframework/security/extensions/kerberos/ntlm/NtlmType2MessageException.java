package org.springframework.security.extensions.kerberos.ntlm;


public class NtlmType2MessageException extends NtlmException {

	private static final long serialVersionUID = 1L;

	private byte[] token;

	public NtlmType2MessageException(byte[] token) {
		super("NtlmType2MessageException");
		this.token = token;
	}

	public byte[] getToken() {
		return token;
	}

}
