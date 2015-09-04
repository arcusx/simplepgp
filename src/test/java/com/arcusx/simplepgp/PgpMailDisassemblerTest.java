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

public class PgpMailDisassemblerTest
{
	private Session session = Session.getDefaultInstance(new Properties());

	@Test
	public void disassemble() throws Exception
	{
		MimeMessage message = new MimeMessage(this.session, getClass().getResourceAsStream("pgp-encrypted.eml"));

		String pgpData = new PgpMailDisassembler(message).getEncryptedPgpData();

		assertEquals("-----BEGIN PGP MESSAGE-----\r\n...\r\n-----END PGP MESSAGE-----\r\n", pgpData);
	}

}
