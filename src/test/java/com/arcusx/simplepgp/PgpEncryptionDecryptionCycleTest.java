/**
 * This source code is part of arcusx-simplepgp.
 * 
 * It is subject to the license terms in the LICENSE file found in
 * the top-level directory of this distribution and at 
 * https://github.com/arcusx/simplepgp/blob/master/LICENSE.
 */

package com.arcusx.simplepgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URL;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class PgpEncryptionDecryptionCycleTest
{
	private PgpDataEncryptor encryptor = new PgpDataEncryptor();

	private PgpDataDecryptor decryptor = new PgpDataDecryptor();

	@Test
	public void encryptAndDecrypt() throws Exception
	{
		String plainMessage = "Request";

		String encryptedMessage = encrypt(plainMessage, PgpKeys.BOB_PUBLIC_KEY);
		assertNotNull(encryptedMessage);

		String decryptedMessage = decrypt(encryptedMessage, PgpKeys.BOB_PRIVATE_KEY, PgpKeys.ALICE_PUBLIC_KEY);
		assertEquals(decryptedMessage, plainMessage);
	}

	private String decrypt(String encryptedMessage, URL recipientPrivateKey, URL senderPublicKey) throws Exception
	{
		ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
		this.decryptor.decryptAndVerify(new ByteArrayInputStream(encryptedMessage.getBytes("UTF-8")),
				recipientPrivateKey.openStream(), senderPublicKey.openStream(), plainOut);

		String plainMessage = new String(plainOut.toByteArray(), "UTF-8");
		return plainMessage;
	}

	private String encrypt(String plainMessage, URL recipientPublicKey) throws Exception
	{
		ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
		this.encryptor.encryptAndSign(new ByteArrayInputStream(plainMessage.getBytes("UTF-8")),
				recipientPublicKey.openStream(), "message.txt", PgpKeys.ALICE_PRIVATE_KEY.openStream(), encryptedOut,
				true);
		String encryptedMessage = new String(encryptedOut.toByteArray(), "UTF-8");
		return encryptedMessage;
	}
}
