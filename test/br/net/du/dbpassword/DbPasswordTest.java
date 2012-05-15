package br.net.du.dbpassword;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class DbPasswordTest {

	private String password = "senha";

	@Test
	public void sha1sumTest() {
		String hash = "bac6ed9bc78f296f631b432a1e0698c79d8046db";
		assertEquals(hash,
				new DbPassword("my shared secret").sha1sum("password", "salt"));
	}

	@Test
	public void testMatches() {
		String hash = "abcd2d4ef79eab978f1ae076674b21692ba43dc7";
		assertTrue(new DbPassword("my shared secret").matches(password, hash));
	}

	@Test
	public void testEncode() {
		int hashOffset = 4;
		DbPassword dbp = new DbPassword("my shared secret");
		String encoded = dbp.encode(password);
		assertEquals(dbp.getLastSalt(), encoded.substring(0, hashOffset));
		assertTrue(dbp.matches(password, encoded));
	}

}
