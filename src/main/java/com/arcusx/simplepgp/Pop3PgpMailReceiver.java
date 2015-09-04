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
import javax.mail.Flags;
import javax.mail.Folder;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Store;
import javax.mail.internet.MimeMessage;

import org.bouncycastle.openpgp.PGPException;

public class Pop3PgpMailReceiver
{
	private boolean debug = false;
	private String host = "localhost";
	private int port = 110;
	private String user;
	private String password;
	private String senderPublicKey;
	private String recipientPrivateKey;

	private PgpDataDecryptor decryptor = new PgpDataDecryptor();

	public Pop3PgpMailReceiver()
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

	public void setSenderPublicKey(String senderPublicKey)
	{
		this.senderPublicKey = senderPublicKey;
	}

	public void setRecipientPrivateKey(String recipientPrivateKey)
	{
		this.recipientPrivateKey = recipientPrivateKey;
	}

	/**
	 * Fetch a PGP mail via POP3, decrypt and verifiy.
	 * 
	 * @return The message body or null if no message available.
	 */
	public String fetch() throws IOException, MessagingException, PGPException
	{
		Session mailSession = getMailSession();

		Store store = mailSession.getStore();
		store.connect();
		Folder inbox = store.getFolder("INBOX");
		try
		{
			inbox.open(Folder.READ_WRITE);
			int messageCount = inbox.getMessageCount();
			for (int i = 1; i <= messageCount; ++i)
			{
				MimeMessage message = (MimeMessage) inbox.getMessage(1);

				PgpMailDisassembler mailDisassembler = new PgpMailDisassembler(message);
				if (mailDisassembler.isEncryptedPgpMail())
				{
					String encryptedPgpData = mailDisassembler.getEncryptedPgpData();
					String mailData = this.decryptor.decryptAndVerify(encryptedPgpData, this.recipientPrivateKey,
							this.senderPublicKey);
					inbox.setFlags(new Message[] { message}, new Flags(Flags.Flag.DELETED), true);
					inbox.close(true);
					return mailData;
				}
			}

			return null;
		}
		finally
		{
			if (inbox != null && inbox.isOpen())
			{
				inbox.close(false);
			}
		}
	}

	private Session getMailSession()
	{
		Properties props = new Properties();
		props.setProperty("mail.debug", String.valueOf(this.debug));
		props.setProperty("mail.host", this.host);
		props.setProperty("mail.pop3.port", String.valueOf(this.port));
		props.setProperty("mail.store.protocol", "pop3");
		Authenticator authenticator = new Authenticator()
		{
			@Override
			protected PasswordAuthentication getPasswordAuthentication()
			{
				return new PasswordAuthentication(Pop3PgpMailReceiver.this.user, Pop3PgpMailReceiver.this.password);
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
