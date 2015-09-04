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

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

/**
 * Extractor of data from PGP mails.
 * 
 * @author conni
 */
public class PgpMailDisassembler
{
	private MimeMessage mimeMessage;

	public PgpMailDisassembler(MimeMessage mimeMessage)
	{
		this.mimeMessage = mimeMessage;
	}

	public boolean isEncryptedPgpMail() throws MessagingException
	{
		String contentType = this.mimeMessage.getContentType();
		return contentType.contains("application/pgp-encrypted");
	}

	public String getEncryptedPgpData() throws IOException, MessagingException
	{
		if (!isEncryptedPgpMail())
			throw new MessagingException("No encrypted PGP mail.");

		Object messageContent = this.mimeMessage.getContent();
		checkIsMultipart(messageContent);

		MimeMultipart multipart = (MimeMultipart) messageContent;
		return getPgpEncryptedDataFrom(multipart);
	}

	private void checkIsMultipart(Object messageContent)
	{
		if (isMultipartMessage(messageContent))
			throw new IllegalStateException("Message is not multipart message. So it cannot be a PGP mail.");
	}

	private boolean isMultipartMessage(Object messageContent)
	{
		return !(messageContent instanceof MimeMultipart);
	}

	private String getPgpEncryptedDataFrom(MimeMultipart multipart) throws MessagingException, IOException
	{
		int partCount = multipart.getCount();
		for (int i = 0; i < partCount; ++i)
		{
			Object bodyPart = multipart.getBodyPart(i);

			if (!(bodyPart instanceof MimeBodyPart))
				continue;

			MimeBodyPart mimeBodyPart = (MimeBodyPart) bodyPart;
			String contentType = mimeBodyPart.getContentType();
			if (contentType.startsWith("application/octet-stream"))
			{
				String content = getContentAsStringFrom(mimeBodyPart);
				checkIsAsciiArmoredPgp(content);
				return content;
			}
		}

		throw new IllegalStateException("Part with encrypted data not found.");
	}

	private String getContentAsStringFrom(MimeBodyPart mimeBodyPart) throws IOException, MessagingException
	{
		Object contentObject = mimeBodyPart.getContent();
		if (contentObject instanceof String)
		{
			return (String) contentObject;
		}
		else if (contentObject instanceof InputStream)
		{
			InputStream contentIn = (InputStream) mimeBodyPart.getContent();
			return IOUtils.toString(contentIn, "UTF-8");
		}

		throw new IllegalStateException("Dont know how to handle content of type " + contentObject);
	}

	private void checkIsAsciiArmoredPgp(String content)
	{
		if (!content.contains("-BEGIN PGP MESSAGE-"))
			throw new IllegalArgumentException("Content is not ASCII armored PGP data.");
	}
}
