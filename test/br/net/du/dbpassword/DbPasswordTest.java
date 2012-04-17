package br.net.du.dbpassword;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.NoSuchAlgorithmException;

import org.junit.Test;

import br.net.du.dbpassword.DbPassword;

public class DbPasswordTest {

	private String password = "senha";

	@Test
	public void sha1sumTest() throws NoSuchAlgorithmException {
		String hash = "7751a23fa55170a57e90374df13a3ab78efe0e99";
		assertEquals(hash,
				new DbPassword("my shared secret", 4).sha1sum(password));
	}

	@Test
	public void testMatches() throws NoSuchAlgorithmException {
		String hash = "abcd2d4ef79eab978f1ae076674b21692ba43dc7";
		assertTrue(new DbPassword("my shared secret", 4)
				.matches(password, hash));
	}

	@Test
	public void testEncode() throws NoSuchAlgorithmException {
		int hashOffset = 4;
		DbPassword dbp = new DbPassword("my shared secret", hashOffset);
		String encoded = dbp.encode(password);
		assertEquals(dbp.getLastSalt(), encoded.substring(0, hashOffset));
		assertTrue(dbp.matches(password, encoded));
	}

}
