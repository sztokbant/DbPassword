package br.net.du.dbpassword;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class DbPasswordTest {

	private String password = "senha";

	@Test
	public void sha1sumTest() throws Exception {
		String hash = "bac6ed9bc78f296f631b432a1e0698c79d8046db";
		assertEquals(hash,
				new DbPassword("my shared secret").sha1sum("password", "salt"));
	}

	@Test
	public void sha1sumTestThatWasFailing() throws Exception {
		String hash = "050f505210c108d3edede76626009b3dbc940c0f";
		assertEquals(
				hash,
				new DbPassword(
						"this secret phrase enhances the protection of our passwords")
						.sha1sum("153000", "ffac"));
	}

	@Test
	public void yetAnotherSha1sumTestThatWasFailing() throws Exception {
		String hash = "0594936720627008a8c019da0727d8a41deb4b0c";
		assertEquals(
				hash,
				new DbPassword(
						"this secret phrase enhances the protection of our passwords")
						.sha1sum("marcos", "35c4"));
	}

	@Test
	public void testMatches() throws Exception {
		String hash = "abcd2d4ef79eab978f1ae076674b21692ba43dc7";
		assertTrue(new DbPassword("my shared secret").matches(password, hash));
	}

	@Test
	public void testEncode() throws Exception {
		DbPassword dbp = new DbPassword("my shared secret");
		String encoded = dbp.encode(password);
		assertEquals(dbp.getLastSalt(),
				encoded.substring(0, DbPassword.HASH_OFFSET));
		assertTrue(dbp.matches(password, encoded));
	}

}
