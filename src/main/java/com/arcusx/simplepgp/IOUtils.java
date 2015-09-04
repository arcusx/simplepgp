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
