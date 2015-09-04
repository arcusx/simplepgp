/**
 * This source code is part of arcusx-simplepgp.
 * 
 * It is subject to the license terms in the LICENSE file found in
 * the top-level directory of this distribution and at 
 * https://github.com/arcusx/simplepgp/blob/master/LICENSE.
 */

package com.arcusx.simplepgp;

import java.security.Provider;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Setup of Security Provider.
 * 
 * @author conni
 */
class SecuritySetup
{
	private static final Logger logger = Logger.getLogger(SecuritySetup.class.getName());

	static
	{
		try
		{
			Provider provider = (Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider")
					.newInstance();
			Security.addProvider(provider);
		}
		catch (ClassNotFoundException ex)
		{
			logger.log(Level.SEVERE, "Bouncycastle JCE provider is required and not found.", ex);
		}
		catch (Exception ex)
		{
			logger.log(Level.SEVERE, "Bouncycastle JCE provider could not be instantiated.", ex);
		}
	}

	static void apply()
	{
		// laoding is sufficient
	}

	private SecuritySetup()
	{
	}
}
