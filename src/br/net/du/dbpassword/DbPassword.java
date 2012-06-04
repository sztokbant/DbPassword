package br.net.du.dbpassword;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Formatter;
import java.util.Random;

public class DbPassword {

	public static final int HASH_OFFSET = 4;

	private String sharedSecret;
	private String lastSalt;
	private Random random;

	public DbPassword(String sharedSecret) {
		random = new SecureRandom();
		this.sharedSecret = sharedSecret;
	}

	public boolean matches(String password, String hash) {
		hash = hash.toLowerCase();
		String salt = hash.substring(0, HASH_OFFSET);
		String sha1 = sha1sum(password, salt);
		return sha1.substring(0, sha1.length() - HASH_OFFSET).equals(hash.substring(HASH_OFFSET));
	}

	public String encode(String password) {
		String salt = newSalt();
		String sha1 = sha1sum(password, salt);
		String encoded = salt + sha1.substring(0, sha1.length() - HASH_OFFSET);
		return encoded;
	}

	String getLastSalt() {
		return lastSalt;
	}

	String sha1sum(String password, String salt) {
		String input = String.format("%s%s%s", password, salt, sharedSecret);

		MessageDigest md;

		try {
			md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}

		return byteArray2Hex(md.digest(input.getBytes()));
	}

	private String byteArray2Hex(final byte[] hash) {
		Formatter formatter = new Formatter();
		for (byte b : hash) {
			formatter.format("%02x", b);
		}
		return formatter.toString();
	}

	private String newSalt() {
		lastSalt = String.format("%04x", random.nextInt(0xffff));
		return lastSalt;
	}
}
