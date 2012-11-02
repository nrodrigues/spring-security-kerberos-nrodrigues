package org.springframework.security.extensions.kerberos.spnego;

public abstract class SpnegoToken {

	// Default max size as 65K
	public static int TOKEN_MAX_SIZE = 66560;

	protected byte[] mechanismToken;
	protected byte[] mechanismList;
	protected String mechanism;

	public static SpnegoToken parse(byte[] token) throws DecodingException {
		SpnegoToken spnegoToken = null;

		if (token.length <= 0)
			throw new DecodingException("spnego.token.empty", null);

		switch (token[0]) {
		case (byte) 0x60:
			spnegoToken = new SpnegoInitToken(token);
			break;
		case (byte) 0xa1:
			spnegoToken = new SpnegoTargToken(token);
			break;
		case (byte) 'N':
			spnegoToken = new SpnegoTargToken(SpnegoTargToken.UNSPECIFIED_RESULT, SpnegoConstants.NTLMSSP_MECHANISM, token, null);
			break;
		default:
			spnegoToken = null;
			throw new DecodingException("spnego.token.invalid", null);
		}

		return spnegoToken;
	}

	public byte[] getMechanismToken() {
		return mechanismToken;
	}

	public byte[] getMechanismList() {
		return mechanismList;
	}

	public String getMechanism() {
		return mechanism;
	}

}
