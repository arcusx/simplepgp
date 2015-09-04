/**
 * This source code is part of arcusx-simplepgp.
 * 
 * It is subject to the license terms in the LICENSE file found in
 * the top-level directory of this distribution and at 
 * https://github.com/arcusx/simplepgp/blob/master/LICENSE.
 */

package com.arcusx.simplepgp;

import java.io.IOException;
import java.util.Properties;

import javax.mail.Authenticator;
import javax.mail.MessagingException;
import javax.mail.NoSuchProviderException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.MimeMessage;

import org.bouncycastle.openpgp.PGPException;

public class SmtpPgpMailSender
{
	private boolean debug = false;
	private String host = "localhost";
	private int port = 25;
	private String user;
	private String password;
	private String recipient;
	private String sender;
	private String recipientPublicKey;
	private String senderPrivateKey;
	private String subject;

	private PgpDataEncryptor encryptor = new PgpDataEncryptor();

	public SmtpPgpMailSender()
	{
	}

	public void setDebug(boolean debug)
	{
		this.debug = debug;
	}

	public void setUser(String user)
	{
		this.user = user;
	}

	public void setHost(String host)
	{
		this.host = host;
	}

	public void setPort(int port)
	{
		this.port = port;
	}

	public void setPassword(String password)
	{
		this.password = password;
	}

	public void setRecipient(String recipient)
	{
		this.recipient = recipient;
	}

	public void setRecipientPublicKey(String recipientPublicKey)
	{
		this.recipientPublicKey = recipientPublicKey;
	}

	public void setSender(String sender)
	{
		this.sender = sender;
	}

	public void setSenderPrivateKey(String senderPrivateKey)
	{
		this.senderPrivateKey = senderPrivateKey;
	}

	public void setSubject(String subject)
	{
		this.subject = subject;
	}

	public void send(String mailData) throws IOException, MessagingException, PGPException
	{
		String encryptedPgpData = encrypt(mailData);

		sendPgpMail(encryptedPgpData);
	}

	private void sendPgpMail(String encryptedPgpData)
			throws AddressException, MessagingException, IOException, NoSuchProviderException
	{
		Session mailSession = getMailSession();
		MimeMessage mimeMessage = new PgpMailAssembler(mailSession).withRecipient(this.recipient)
				.withSender(this.sender).withSubject(this.subject).withData(encryptedPgpData).build();

		Transport transport = mailSession.getTransport("smtp");
		transport.connect();
		transport.sendMessage(mimeMessage, mimeMessage.getAllRecipients());
		transport.close();
	}

	private String encrypt(String mailData) throws IOException, PGPException
	{
		String encryptedPgpData = this.encryptor.encryptAndSign(mailData, this.recipientPublicKey,
				this.senderPrivateKey);
		return encryptedPgpData;
	}

	private Session getMailSession()
	{
		Properties props = new Properties();
		props.setProperty("mail.debug", String.valueOf(this.debug));
		props.setProperty("mail.host", this.host);
		props.setProperty("mail.transport.protocol", "smtp");
		props.setProperty("mail.smtp.port", String.valueOf(this.port));
		props.setProperty("mail.smtp.auth", String.valueOf(this.user != null && this.password != null));
		Authenticator authenticator = new Authenticator()
		{
			@Override
			protected PasswordAuthentication getPasswordAuthentication()
			{
				return new PasswordAuthentication(SmtpPgpMailSender.this.user, SmtpPgpMailSender.this.password);
			}
		};
		Session mailSession = buildMailSession(props, authenticator);
		return mailSession;
	}

	protected Session buildMailSession(Properties props, Authenticator authenticator)
	{
		return Session.getDefaultInstance(props, authenticator);
	}
}
