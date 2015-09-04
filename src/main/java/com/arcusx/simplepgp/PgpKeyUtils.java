/**
 * This source code is part of arcusx-simplepgp.
 * 
 * It is subject to the license terms in the LICENSE file found in
 * the top-level directory of this distribution and at 
 * https://github.com/arcusx/simplepgp/blob/master/LICENSE.
 */

package com.arcusx.simplepgp;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.NoSuchElementException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

/**
 * Helper for reading and extracting infos from PGP keys.
 * 
 * @author conni
 */
class PgpKeyUtils
{
	public static PGPPublicKey readPublicKey(InputStream keyFile) throws IOException, PGPException
	{

		InputStream in = null;
		try
		{
			in = PGPUtil.getDecoderStream(keyFile);
			PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in);

			PGPPublicKey key = getFirstEncryptionKey(pgpPub);
			if (key == null)
			{
				throw new IllegalArgumentException("Can't find encryption key in key ring.");
			}
			return key;
		}
		finally
		{
			if (in != null)
			{
				in.close();
			}
		}
	}

	@SuppressWarnings("unchecked")
	private static PGPPublicKey getFirstEncryptionKey(PGPPublicKeyRingCollection pgpPub)
	{
		Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();
		while (rIt.hasNext())
		{
			PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
			Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();
			while (kIt.hasNext())
			{
				PGPPublicKey k = (PGPPublicKey) kIt.next();
				if (k.isEncryptionKey())
				{
					return k;
				}
			}
		}
		return null;
	}

	public static PGPSecretKey findSecretKey(InputStream privateKeyIn) throws PGPException, IOException
	{
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(privateKeyIn));
		for (Iterator<PGPSecretKeyRing> iter = pgpSec.getKeyRings(); iter.hasNext();)
		{
			PGPSecretKeyRing pgpSecretKeyRing = iter.next();
			for (Iterator<PGPSecretKey> keysIter = pgpSecretKeyRing.getSecretKeys(); keysIter.hasNext();)
			{
				PGPSecretKey secretKey = keysIter.next();
				return secretKey;
			}
		}

		throw new NoSuchElementException("No private key found.");
	}

	public static PGPPrivateKey getPrivateKeyFrom(PGPSecretKey secretKey) throws PGPException, IOException
	{
		PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
				.build("".toCharArray());
		return secretKey.extractPrivateKey(decryptor);
	}

	public static String getUserIdFrom(PGPSecretKey secretKey)
	{
		return (String) secretKey.getUserIDs().next();
	}

}
