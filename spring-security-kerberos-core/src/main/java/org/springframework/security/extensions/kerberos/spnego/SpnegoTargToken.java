package org.springframework.security.extensions.kerberos.spnego;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

public class SpnegoTargToken extends SpnegoToken {

	public static final int UNSPECIFIED_RESULT = -1;
	public static final int ACCEPT_COMPLETED = 0;
	public static final int ACCEPT_INCOMPLETE = 1;
	public static final int REJECTED = 2;

	private int result = UNSPECIFIED_RESULT;

	public SpnegoTargToken(byte[] token) throws DecodingException {
		ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(token));
		ASN1TaggedObject tagged;
		try {
			tagged = DecodingUtil.as(ASN1TaggedObject.class, stream);
		} catch (IOException e) {
			throw new DecodingException("spnego.token.malformed", e);
		}

		ASN1Sequence sequence = ASN1Sequence.getInstance(tagged, true);
		Enumeration<?> fields = sequence.getObjects();
		while (fields.hasMoreElements()) {
			tagged = DecodingUtil.as(ASN1TaggedObject.class, fields);
			switch (tagged.getTagNo()) {
			case 0:
				DEREnumerated enumerated = DEREnumerated.getInstance(tagged, true);
				result = enumerated.getValue().intValue();
				break;
			case 1:
				DERObjectIdentifier mechanismOid = DERObjectIdentifier.getInstance(tagged, true);
				mechanism = mechanismOid.getId();
				break;
			case 2:
				ASN1OctetString mechanismTokenString = ASN1OctetString.getInstance(tagged, true);
				mechanismToken = mechanismTokenString.getOctets();
				break;
			case 3:
				ASN1OctetString mechanismListString = ASN1OctetString.getInstance(tagged, true);
				mechanismList = mechanismListString.getOctets();
				break;
			default:
				throw new DecodingException("spnego.field.invalid", null);
			}
		}
	}

	public SpnegoTargToken(int result, String mechanism, byte[] mechanismToken, byte[] mechanismList) {
		this.result = result;
		this.mechanism = mechanism;
		this.mechanismToken = mechanismToken;
		this.mechanismList = mechanismList;
	}

	public byte[] toByteArray() {
		try {
			ByteArrayOutputStream collector = new ByteArrayOutputStream();
			DEROutputStream der = new DEROutputStream(collector);
			ASN1EncodableVector fields = new ASN1EncodableVector();
			int result = getResult();
			if (result != UNSPECIFIED_RESULT) {
				fields.add(new DERTaggedObject(true, 0, new DEREnumerated(result)));
			}
			String mechanism = getMechanism();
			if (mechanism != null) {
				fields.add(new DERTaggedObject(true, 1, new DERObjectIdentifier(mechanism)));
			}
			byte[] mechanismToken = getMechanismToken();
			if (mechanismToken != null) {
				fields.add(new DERTaggedObject(true, 2, new DEROctetString(mechanismToken)));
			}
			if (mechanismList != null) {
				fields.add(new DERTaggedObject(true, 3, new DEROctetString(mechanismList)));
			}
			der.writeObject(new DERTaggedObject(true, 1, new DERSequence(fields)));
			return collector.toByteArray();
		} catch (IOException ex) {
			throw new IllegalStateException(ex.getMessage(), ex);
		}
	}

	public int getResult() {
		return result;
	}

	@Override
	public String toString() {
		return "SpnegoTargToken [result=" + result + ", mechanismToken=" + Arrays.toString(mechanismToken) + ", mechanismList="
				+ Arrays.toString(mechanismList) + ", mechanism=" + mechanism + "]";
	}

}
