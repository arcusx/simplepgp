/**
 * This source code is part of arcusx-simplepgp.
 * 
 * It is subject to the license terms in the LICENSE file found in
 * the top-level directory of this distribution and at 
 * https://github.com/arcusx/simplepgp/blob/master/LICENSE.
 */

package com.arcusx.simplepgp;

import java.util.Properties;

import javax.mail.Session;
import javax.mail.internet.MimeMessage;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class PgpMailAssemblerTest
{
	private Session session = Session.getDefaultInstance(new Properties());

	private String fakePgpData = "-----BEGIN PGP MESSAGE-----\n...\n-----END PGP MESSAGE-----";

	@Test
	public void happyPath() throws Exception
	{
		MimeMessage message = new PgpMailAssembler(session).withHeader("X-Header", "Value")
				.withSender("sender@example.com").withRecipient("recipient@example.com").withData(fakePgpData).build();
		assertNotNull(message);

		String pgpData = new PgpMailDisassembler(message).getEncryptedPgpData();
		assertEquals(fakePgpData, pgpData);
	}
}
