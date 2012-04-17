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

	public boolean matches(String password, String hash)
			throws NoSuchAlgorithmException {
		String salt = hash.substring(0, HASH_OFFSET);
		String sha1 = sha1sum(password + salt + sharedSecret);
		return sha1.substring(0, sha1.length() - HASH_OFFSET).equals(
				hash.substring(HASH_OFFSET));
	}

	public String encode(String password) throws NoSuchAlgorithmException {
		String salt = newSalt();
		String sha1 = sha1sum(password + salt + sharedSecret);
		String encoded = salt + sha1.substring(0, sha1.length() - HASH_OFFSET);
		return encoded;
	}

	String getLastSalt() {
		return lastSalt;
	}

	String sha1sum(String password) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		md.update(password.getBytes());
		BigInteger hash = new BigInteger(1, md.digest());
		return hash.toString(16);
	}

	private String newSalt() {
		lastSalt = String.format("%04x", new Random().nextInt(0xffff));
		return lastSalt;
	}
}
