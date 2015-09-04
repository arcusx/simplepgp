/**
 * This source code is part of arcusx-simplepgp.
 * 
 * It is subject to the license terms in the LICENSE file found in
 * the top-level directory of this distribution and at 
 * https://github.com/arcusx/simplepgp/blob/master/LICENSE.
 */

package com.arcusx.simplepgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

/**
 * Simple interface to PGP decryption.
 * 
 * @author conni
 */
public class PgpDataDecryptor
{
	private static final int BUFFER_SIZE = 4 * 1024;

	static
	{
		SecuritySetup.apply();
	}

	public PgpDataDecryptor()
	{
	}

	public String decryptAndVerify(String encryptedData, String privateKey, String publicKey)
			throws PGPException, IOException
	{
		InputStream encryptedIn = IOUtils.toInputStream(encryptedData, "UTF-8");
		InputStream privateKeyIn = IOUtils.toInputStream(privateKey, "UTF-8");
		InputStream publicKeyIn = IOUtils.toInputStream(publicKey, "UTF-8");
		ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

		decryptAndVerify(encryptedIn, privateKeyIn, publicKeyIn, plainOut);
		return new String(plainOut.toByteArray(), "UTF-8");
	}

	public void decryptAndVerify(InputStream encryptedIn, InputStream privateKeyIn, InputStream publicKeyIn,
			OutputStream plainOut) throws PGPException, IOException
	{
		decrypt(encryptedIn, privateKeyIn, publicKeyIn, plainOut, true);
	}

	public void decrypt(InputStream encryptedIn, InputStream privateKeyIn, InputStream publicKeyIn,
			OutputStream plainOut, boolean signatureRequired) throws PGPException, IOException
	{
		encryptedIn = PGPUtil.getDecoderStream(encryptedIn);

		try
		{
			JcaPGPObjectFactory pgpObjectFactory = new JcaPGPObjectFactory(encryptedIn);

			Object o = pgpObjectFactory.nextObject();

			//
			// the first object might be a PGP marker packet.
			//
			PGPEncryptedDataList enc;
			if (o instanceof PGPEncryptedDataList)
			{
				enc = (PGPEncryptedDataList) o;
			}
			else
			{
				enc = (PGPEncryptedDataList) pgpObjectFactory.nextObject();
			}

			//
			// find the secret key
			//
			Iterator it = enc.getEncryptedDataObjects();
			PGPPrivateKey privateKey = null;
			PGPPublicKeyEncryptedData publicKeyEncryptedData = null;
			PGPSecretKeyRingCollection privateKeyRingCollection = new PGPSecretKeyRingCollection(
					PGPUtil.getDecoderStream(privateKeyIn), new JcaKeyFingerprintCalculator());

			while (privateKey == null && it.hasNext())
			{
				publicKeyEncryptedData = (PGPPublicKeyEncryptedData) it.next();
				privateKey = findSecretKey(privateKeyRingCollection, publicKeyEncryptedData.getKeyID(),
						"".toCharArray());
			}

			if (privateKey == null)
			{
				throw new IllegalArgumentException("Secret key for message not found.");
			}

			PublicKeyDataDecryptorFactory decryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
					.setProvider("BC").build(privateKey);
			InputStream clearTextIn = publicKeyEncryptedData.getDataStream(decryptorFactory);

			PGPOnePassSignature onePassSignature = null;
			JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(clearTextIn);

			Object message = pgpFact.nextObject();
			if (message instanceof PGPCompressedData)
			{
				PGPCompressedData cData = (PGPCompressedData) message;
				pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

				message = pgpFact.nextObject();
			}

			if (message instanceof PGPOnePassSignatureList)
			{
				PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList) message;
				onePassSignature = onePassSignatureList.get(0);
				message = pgpFact.nextObject();
			}

			if (onePassSignature == null && signatureRequired)
			{
				throw new SecurityException("No signature object found.");
			}

			if (message instanceof PGPLiteralData)
			{
				PGPLiteralData literalData = (PGPLiteralData) message;
				InputStream literalDataIn = literalData.getInputStream();

				PGPPublicKey publicKey = PgpKeyUtils.readPublicKey(publicKeyIn);
				if (onePassSignature != null)
				{
					onePassSignature.init(new BcPGPContentVerifierBuilderProvider(), publicKey);
				}

				int len = 0;
				byte[] buf = new byte[BUFFER_SIZE];
				while ((len = literalDataIn.read(buf, 0, buf.length)) >= 0)
				{
					if (onePassSignature != null)
					{
						onePassSignature.update(buf, 0, len);
					}

					plainOut.write(buf, 0, len);
				}

				if (onePassSignature != null)
				{
					PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();
					PGPSignature signature = p3.get(0);
					if (!onePassSignature.verify(signature))
						throw new PGPException("Signature invalid.");
				}

				plainOut.close();
			}
			else
			{
				throw new PGPException("message is not a simple encrypted file - type unknown." + message);
			}

			if (!publicKeyEncryptedData.isIntegrityProtected())
				throw new IllegalStateException("Message is not integrity protected.");

			if (!publicKeyEncryptedData.verify())
				throw new IllegalStateException("Message is integrity protected but integrity check failed.");
		}
		catch (NoSuchProviderException ex)
		{
			throw new PGPException("Decryption failed.", ex);
		}
		finally
		{
			IOUtils.closeQuietly(encryptedIn);
			IOUtils.closeQuietly(privateKeyIn);
			IOUtils.closeQuietly(publicKeyIn);
			IOUtils.closeQuietly(plainOut);
		}
	}

	private static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
			throws PGPException, NoSuchProviderException
	{
		PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

		if (pgpSecKey == null)
		{
			return null;
		}

		return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
	}
}
