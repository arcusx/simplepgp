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

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMessage.RecipientType;
import javax.mail.internet.MimeMultipart;

/**
 * Builder for PGP mails.
 * 
 * @author conni
 */
public class PgpMailAssembler
{
	private Session session;

	private String recipient;
	private String sender;
	private String subject;

	private String data;

	public PgpMailAssembler(Session session)
	{
		this.session = session;
	}

	public PgpMailAssembler withSender(String sender)
	{
		this.sender = sender;
		return this;
	}

	public PgpMailAssembler withRecipient(String recipient)
	{
		this.recipient = recipient;
		return this;
	}

	public PgpMailAssembler withSubject(String subject)
	{
		this.subject = subject;
		return this;
	}

	public PgpMailAssembler withData(String data)
	{
		this.data = data;
		return this;
	}

	public PgpMailAssembler withData(byte[] data, String charset)
	{
		try
		{
			this.data = new String(data, charset);
			return this;
		}
		catch (IOException ex)
		{
			throw new RuntimeException(ex);
		}
	}

	public byte[] buildAsBytes() throws AddressException, MessagingException, IOException
	{
		MimeMessage mimeMessage = build();
		ByteArrayOutputStream mailOut = new ByteArrayOutputStream();
		mimeMessage.writeTo(mailOut);
		return mailOut.toByteArray();
	}

	public MimeMessage build() throws AddressException, MessagingException, IOException
	{

		MimeMessage mimeMessage = buildBaseMimeMessage();
		if (!isDataPgpEncrypted())
			throw new IllegalArgumentException("No ASCII armor found in data.");

		appendPgpEncryptedMultipart(mimeMessage);
		mimeMessage.saveChanges();

		return mimeMessage;
	}

	private void appendPgpEncryptedMultipart(MimeMessage mimeMessage) throws MessagingException
	{
		MimeMultipart multipartEncrypted = new MimeMultipart("encrypted;protocol=\"application/pgp-encrypted\"");

		MimeBodyPart controlBlock = new MimeBodyPart();
		controlBlock.setContent("Version: 1", "application/pgp-encrypted");
		controlBlock.setHeader("Content-Description", "PGP/MIME version identification");
		multipartEncrypted.addBodyPart(controlBlock);

		MimeBodyPart encryptedDataBlock = new MimeBodyPart();
		encryptedDataBlock.setContent(this.data, "application/octet-stream");
		encryptedDataBlock.setHeader("Content-Description", "OpenPGP encrypted message");
		encryptedDataBlock.setHeader("Content-Disposition", "inline; filename=\"message.asc\"");

		multipartEncrypted.addBodyPart(encryptedDataBlock);

		mimeMessage.setContent(multipartEncrypted);
	}

	private boolean isDataPgpEncrypted()
	{
		return this.data.contains("-BEGIN PGP MESSAGE-");
	}

	private MimeMessage buildBaseMimeMessage() throws MessagingException, AddressException
	{
		MimeMessage mimeMessage = new MimeMessage(this.session);
		mimeMessage.setRecipients(RecipientType.TO, InternetAddress.parse(recipient));
		mimeMessage.setSender(InternetAddress.parse(sender)[0]);
		mimeMessage.setSubject(subject);
		return mimeMessage;
	}
}
