package org.springframework.security.extensions.kerberos.spnego;


public class DecodingException extends Exception {
	private static final long serialVersionUID = 1L;


	public DecodingException(String message) {
		this(message, null);
	}

	public DecodingException(Throwable cause) {
		this(null, cause);
	}

	public DecodingException(String message, Throwable cause) {
		super(message, cause);
	}

}
