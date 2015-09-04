/**
 * This source code is part of arcusx-simplepgp.
 * 
 * It is subject to the license terms in the LICENSE file found in
 * the top-level directory of this distribution and at 
 * https://github.com/arcusx/simplepgp/blob/master/LICENSE.
 */

package com.arcusx.simplepgp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * IO helpers
 * 
 * @author conni
 */
class IOUtils
{
	private static final Logger logger = Logger.getLogger(IOUtils.class.getName());

	public static InputStream toInputStream(String s, String charSet) throws IOException
	{
		return new ByteArrayInputStream(s.getBytes(charSet));
	}

	public static String toString(InputStream in, String charSet) throws IOException
	{
		char[] cbuf = new char[1024 * 4];
		int len = 0;

		InputStreamReader rd = new InputStreamReader(in, charSet);
		StringBuilder buf = new StringBuilder();
		while ((len = (rd.read(cbuf))) != -1)
		{
			buf.append(cbuf, 0, len);
		}
		rd.close();

		return buf.toString();
	}

	public static void closeQuietly(InputStream in)
	{
		try
		{
			if (in != null)
				in.close();
		}
		catch (IOException ex)
		{
			logger.log(Level.WARNING, "Closing failed.", ex);
		}
	}

	public static void closeQuietly(OutputStream out)
	{
		try
		{
			if (out != null)
				out.close();
		}
		catch (IOException ex)
		{
			logger.log(Level.WARNING, "Closing failed.", ex);
		}
	}
}
