package br.net.du.dbpassword;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class DbPassword {

	public static final int HASH_OFFSET = 4;

	private String sharedSecret;
	private String lastSalt;

	public DbPassword(String sharedSecret) {
		this.sharedSecret = sharedSecret;
	}

	public boolean matches(String password, String hash) {
		hash = hash.toLowerCase();
		String salt = hash.substring(0, HASH_OFFSET);
		String sha1 = sha1sum(password, salt);
		return sha1.substring(0, sha1.length() - HASH_OFFSET).equals(
				hash.substring(HASH_OFFSET));
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

		md.update(input.getBytes());
		BigInteger hash = new BigInteger(1, md.digest());
		return hash.toString(16);
	}

	private String newSalt() {
		lastSalt = String.format("%04x", new Random().nextInt(0xffff));
		return lastSalt;
	}
}
