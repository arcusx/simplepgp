/**
 * This source code is part of arcusx-simplepgp.
 * 
 * It is subject to the license terms in the LICENSE file found in
 * the top-level directory of this distribution and at 
 * https://github.com/arcusx/simplepgp/blob/master/LICENSE.
 */

package com.arcusx.simplepgp;

import java.net.URL;

/**
 * PGP keys for testing.
 * 
 * @author conni
 */
public class PgpKeys
{
	public static final URL ALICE_PUBLIC_KEY = PgpKeys.class.getResource("alice.pgppublic.pem");

	public static final URL ALICE_PRIVATE_KEY = PgpKeys.class.getResource("alice.pgpprivate.pem");

	public static final URL BOB_PUBLIC_KEY = PgpKeys.class.getResource("bob.pgppublic.pem");

	public static final URL BOB_PRIVATE_KEY = PgpKeys.class.getResource("bob.pgpprivate.pem");

	private PgpKeys()
	{
	}
}
