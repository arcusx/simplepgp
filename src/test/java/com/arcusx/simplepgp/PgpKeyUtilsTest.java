/**
 * This source code is part of arcusx-simplepgp.
 * 
 * It is subject to the license terms in the LICENSE file found in
 * the top-level directory of this distribution and at 
 * https://github.com/arcusx/simplepgp/blob/master/LICENSE.
 */

package com.arcusx.simplepgp;

import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class PgpKeyUtilsTest
{
	@Test
	public void publicKey() throws Exception
	{
		PGPPublicKey publicKey = PgpKeyUtils.readPublicKey(PgpKeys.ALICE_PUBLIC_KEY.openStream());
		assertNotNull(publicKey);
	}

	@Test
	public void secretKey() throws Exception
	{
		PGPSecretKey secretKey = PgpKeyUtils.findSecretKey(PgpKeys.ALICE_PRIVATE_KEY.openStream());
		assertNotNull(secretKey);

		String userId = PgpKeyUtils.getUserIdFrom(secretKey);
		assertEquals("Alice <alice@example.com>", userId);

		PGPPrivateKey privateKey = PgpKeyUtils.getPrivateKeyFrom(secretKey);
		assertNotNull(privateKey);
	}
}
