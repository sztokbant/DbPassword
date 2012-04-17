package br.net.du.dbpassword;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class DbPassword {

	private String sharedSecret = "";
	private String lastSalt = "";

	public DbPassword(String sharedSecret) {
		this.sharedSecret = sharedSecret;
	}

	public boolean matches(String password, String hash)
			throws NoSuchAlgorithmException {
		String salt = hash.substring(0, 4);
		String sha1 = sha1sum(password + salt + sharedSecret);
		return sha1.substring(0, sha1.length() - 4).equals(hash.substring(4));
	}

	public String encode(String password) throws NoSuchAlgorithmException {
		String salt = newSalt();
		String sha1 = sha1sum(password + salt + sharedSecret);
		String encoded = salt + sha1.substring(0, sha1.length() - 4);
		return encoded;
	}

	String getLastSalt() {
		return lastSalt;
	}

	String sha1sum(String password) throws NoSuchAlgorithmException {
		MessageDigest md;
		
		md = MessageDigest.getInstance("SHA-1");
		
		md.update(password.getBytes());
		
		BigInteger hash = new BigInteger(1, md.digest());
		return hash.toString(16);
	}
	
	private String newSalt() {
		lastSalt = Integer.toHexString(new Random().nextInt(0xffff));
		return lastSalt;
	}
}
