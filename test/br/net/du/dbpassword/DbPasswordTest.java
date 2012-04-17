package br.net.du.dbpassword;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.NoSuchAlgorithmException;

import org.junit.Test;

public class DbPasswordTest {

	private String password = "senha";

	@Test
	public void sha1sumTest() throws NoSuchAlgorithmException {
		String hash = "7751a23fa55170a57e90374df13a3ab78efe0e99";
		assertEquals(hash, new DbPassword("my shared secret").sha1sum(password));
	}

	@Test
	public void testMatches() throws NoSuchAlgorithmException {
		String hash = "abcd2d4ef79eab978f1ae076674b21692ba43dc7";
		assertTrue(new DbPassword("my shared secret").matches(password, hash));
	}

	@Test
	public void testEncode() throws NoSuchAlgorithmException {
		DbPassword dbp = new DbPassword("my shared secret");
		String encoded = dbp.encode(password);
		assertEquals(dbp.getLastSalt(), encoded.substring(0, 4));
		assertTrue(dbp.matches(password, encoded));
	}

}