package org.apache.openmeetings.custom.crypt;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.apache.commons.codec.binary.Base64;
import org.apache.openmeetings.util.crypt.ICrypt;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * SHA512
 *
 */
public class MyCustomCrypt implements ICrypt {
	private static final String SECURE_RND_ALG = "SHA1PRNG";
	private static final ThreadLocal<SecureRandom> rnd = new ThreadLocal<>() {
		@Override
		protected SecureRandom initialValue() {
			SecureRandom sr;
			try {
				sr = SecureRandom.getInstance(SECURE_RND_ALG);
			} catch (NoSuchAlgorithmException e) {
				sr = new SecureRandom();
			}
			return sr;
		}
	};
	private static final int KEY_LENGTH = 128 * 8;
	private static final int ITER = 1000;
	private static final int SALT_LENGTH = 200;

	private static byte[] getSalt(int length) {
		byte[] salt = new byte[length];
		rnd.get().nextBytes(salt);
		return salt;
	}
	private static String hash(String str, byte[] salt) {
		PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA512Digest());
		gen.init(str.getBytes(StandardCharsets.UTF_8), salt, ITER);
		byte[] dk = ((KeyParameter) gen.generateDerivedParameters(KEY_LENGTH)).getKey();
		return Base64.encodeBase64String(dk);
	}

	@Override
	public String hash(String str) {
		if (str == null) {
			return null;
		}
		byte[] salt = getSalt(SALT_LENGTH);
		String h = hash(str, salt);
		return String.format("%s:%s", h, Base64.encodeBase64String(salt));
	}

	@Override
	public boolean verify(String str, String hash) {
		if (str == null) {
			return hash == null;
		}
		if (hash == null) {
			return false;
		}
		String[] ss = hash.split(":");
		if (ss.length != 2) {
			return false;
		}
		try {
			String h1 = ss[0];
			byte[] salt = Base64.decodeBase64(ss[1]);
			String h2 = hash(str, salt);
			return h2.equals(h1);
		} catch (Exception e) {
			return false;
		}
	}

	@Override
	public boolean fallback(String str, String hash) {
		// no-fallback
		return false;
	}

	@Override
	public String randomPassword(int length) {
		return Base64.encodeBase64String(getSalt(length));
	}

}
