/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.cxf.fediz.core;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.apache.cxf.fediz.core.FederationConfiguration;
import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.FederationProcessor;
import org.apache.cxf.fediz.core.FederationProcessorImpl;
import org.apache.cxf.fediz.core.FederationRequest;
import org.apache.cxf.fediz.core.FederationResponse;
import org.junit.BeforeClass;

import junit.framework.Assert;

import static org.apache.cxf.fediz.core.FederationConstants.DEFAULT_ROLE_URI;

public class FederationProcessorTest {

	private static final String TEST_OTHER_ISSUER = "ZFS IDP DEV";
	private static final String TEST_USER = "alice";
	private static final String TEST_TRUSTSTORE_FILE = "stsstore.jks";
	private static final String TEST_TRUSTSTORE_PASSWORD = "stsspass";
	private static final String TEST_RSTR_ISSUER = "DoubleItSTSIssuer";
	private static final String TEST_CERT_CONSTRAINT = ".*CN=www.sts.com.*";
	
	
	private static String sRSTR = null;

    @BeforeClass
	public static void readWResult() {
		InputStream is = null;
		try {
			is = FederationProcessorTest.class.getResourceAsStream("/RSTR.xml");
			if (is == null) {
				throw new FileNotFoundException("Failed to get RSTR.xml");
			}
			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(is));
			StringBuilder stringBuilder = new StringBuilder();
			String line = null;
			while ((line = bufferedReader.readLine()) != null) {
				stringBuilder.append(line + "\n");
			}
			bufferedReader.close();
			sRSTR = stringBuilder.toString();
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (is != null) {
				try {
					is.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		Assert.assertNotNull("RSTR resource null", sRSTR);
		
	}
	
	@org.junit.Test
	public void validateSAML2Token() {
		
		FederationRequest wfReq = new FederationRequest();
		wfReq.setWa(FederationConstants.ACTION_SIGNIN);
		wfReq.setWresult(sRSTR);
		
		FederationConfiguration config = new FederationConfiguration();
		config.setTrustedIssuer(TEST_CERT_CONSTRAINT);
		config.setRoleDelimiter(";");
		config.setRoleURI(FederationConstants.DEFAULT_ROLE_URI);
		config.setTrustStoreFile(TEST_TRUSTSTORE_FILE);
		config.setTrustStorePassword(TEST_TRUSTSTORE_PASSWORD);
		config.setDetectReplayedTokens(false);
		
		FederationProcessor wfProc = new FederationProcessorImpl();
		FederationResponse wfRes = wfProc.processRequest(wfReq, config);
		Assert.assertEquals("Principal name wrong", TEST_USER, wfRes.getUsername());
		Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
	}
	
	
	@org.junit.Test
	public void validateSAML2TokenWithWrongIssuer() {
		
		FederationRequest wfReq = new FederationRequest();
		wfReq.setWa(FederationConstants.ACTION_SIGNIN);
		wfReq.setWresult(sRSTR);
		
		FederationConfiguration config = new FederationConfiguration();
		config.setTrustedIssuer(TEST_OTHER_ISSUER);
		config.setRoleDelimiter(";");
		config.setRoleURI(FederationConstants.DEFAULT_ROLE_URI);
		config.setTrustStoreFile(TEST_TRUSTSTORE_FILE);
		config.setTrustStorePassword(TEST_TRUSTSTORE_PASSWORD);
		config.setDetectReplayedTokens(false);
		
		FederationProcessor wfProc = new FederationProcessorImpl();
		try {
			wfProc.processRequest(wfReq, config);
			Assert.fail("Processing must fail because of wrong issuer configured");
		}
		catch (RuntimeException ex) {
			Assert.assertEquals("Exception expected", "Issuer '" + TEST_RSTR_ISSUER + "' not trusted", ex.getMessage());
		}
	}
	
	@org.junit.Test
	public void validateSAML2TokenForRoles() {
		
		FederationRequest wfReq = new FederationRequest();
		wfReq.setWa(FederationConstants.ACTION_SIGNIN);
		wfReq.setWresult(sRSTR);
		
		FederationConfiguration config = new FederationConfiguration();
		config.setTrustedIssuer(TEST_CERT_CONSTRAINT);
		config.setRoleDelimiter(";");
		config.setRoleURI(DEFAULT_ROLE_URI);
		config.setTrustStoreFile(TEST_TRUSTSTORE_FILE);
		config.setTrustStorePassword(TEST_TRUSTSTORE_PASSWORD);
		config.setDetectReplayedTokens(false);
		
		FederationProcessor wfProc = new FederationProcessorImpl();
		FederationResponse wfRes = wfProc.processRequest(wfReq, config);
		Assert.assertEquals("Principal name wrong", TEST_USER, wfRes.getUsername());
		Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
		Assert.assertEquals("One role must be found", 1, wfRes.getRoles().size());
	}
	
 

}
