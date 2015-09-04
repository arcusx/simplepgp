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
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

/**
 * Simple interface to PGP encryption.
 * 
 * @author conni
 */
public class PgpDataEncryptor
{
	static
	{
		SecuritySetup.apply();
	}

	private static final int BUFFER_SIZE = 4 * 1024;

	public PgpDataEncryptor()
	{
	}

	public String encryptAndSign(String plainData, String recipientPublicKey, String senderPrivateKey)
			throws IOException, PGPException
	{
		InputStream plainDataIn = IOUtils.toInputStream(plainData, "UTF-8");
		InputStream recipientPublicKeyIn = IOUtils.toInputStream(recipientPublicKey, "UTF-8");
		InputStream senderPrivateKeyIn = IOUtils.toInputStream(senderPrivateKey, "UTF-8");
		ByteArrayOutputStream encryptedDataOut = new ByteArrayOutputStream();
		encryptAndSign(plainDataIn, recipientPublicKeyIn, "message.asc", senderPrivateKeyIn, encryptedDataOut, true);
		return new String(encryptedDataOut.toByteArray(), "UTF-8");
	}

	public void encryptAndSign(InputStream dataIn, InputStream recipientPublicKeyFileIn, String dataFileName,
			InputStream senderPrivateKeyFileIn, OutputStream dataOut, boolean isArmoredOutput)
					throws IOException, PGPException
	{
		PGPCompressedDataGenerator comData = null;
		try
		{
			OutputStream out = dataOut;
			PGPPublicKey recipientPublicKey = PgpKeyUtils.readPublicKey(recipientPublicKeyFileIn);

			if (isArmoredOutput)
			{
				out = new ArmoredOutputStream(out);
			}

			BcPGPDataEncryptorBuilder dataEncryptor = new BcPGPDataEncryptorBuilder(PGPEncryptedData.TRIPLE_DES);
			dataEncryptor.setWithIntegrityPacket(true);
			dataEncryptor.setSecureRandom(new SecureRandom());

			PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptor);
			encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(recipientPublicKey));

			OutputStream encryptedOut = encryptedDataGenerator.open(out, new byte[BUFFER_SIZE]);

			// Initialize compressed data generator
			PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
			OutputStream compressedOut = compressedDataGenerator.open(encryptedOut, new byte[BUFFER_SIZE]);

			// Initialize signature generator
			final PGPSecretKey senderSecretKey = PgpKeyUtils.findSecretKey(senderPrivateKeyFileIn);
			PGPPrivateKey privateKey = PgpKeyUtils.getPrivateKeyFrom(senderSecretKey);

			PGPContentSignerBuilder signerBuilder = new BcPGPContentSignerBuilder(
					senderSecretKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1);

			PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(signerBuilder);
			signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

			PGPSignatureSubpacketGenerator signatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
			signatureSubpacketGenerator.setSignerUserID(false, PgpKeyUtils.getUserIdFrom(senderSecretKey));
			signatureGenerator.setHashedSubpackets(signatureSubpacketGenerator.generate());
			signatureGenerator.generateOnePassVersion(false).encode(compressedOut);

			// Initialize literal data generator
			PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
			OutputStream literalOut = literalDataGenerator.open(compressedOut, PGPLiteralData.BINARY, dataFileName,
					new Date(), new byte[BUFFER_SIZE]);

			byte[] buf = new byte[BUFFER_SIZE];
			int len;
			while ((len = dataIn.read(buf)) > 0)
			{
				literalOut.write(buf, 0, len);
				signatureGenerator.update(buf, 0, len);
			}
			dataIn.close();
			literalDataGenerator.close();

			// generate the signature, compress, encrypt and write to the "out" stream
			signatureGenerator.generate().encode(compressedOut);
			compressedDataGenerator.close();
			encryptedDataGenerator.close();
			if (isArmoredOutput)
			{
				out.close();
			}
		}
		finally
		{
			if (comData != null)
			{
				comData.close();
			}
			IOUtils.closeQuietly(dataOut);
		}
	}
}
