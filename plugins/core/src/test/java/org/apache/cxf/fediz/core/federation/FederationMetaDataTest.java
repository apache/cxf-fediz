/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.cxf.fediz.core.federation;

import java.io.File;
import java.net.URL;

import javax.servlet.http.HttpServletRequest;
import javax.xml.transform.TransformerException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.apache.cxf.fediz.common.SecurityTestUtil;
import org.apache.cxf.fediz.core.config.FedizConfigurator;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.processor.FederationProcessorImpl;
import org.apache.cxf.fediz.core.processor.FedizProcessor;
import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;

import org.easymock.EasyMock;
import org.junit.AfterClass;
import org.junit.Assert;

import static org.junit.Assert.fail;

public class FederationMetaDataTest {
    private static final String CONFIG_FILE = "fediz_meta_test_config.xml";
    private static final String TEST_REQUEST_URL =
        "https://localhost/fedizhelloworld/FederationMetadata/2007-06/FederationMetadata.xml";
    private static final String CONTEXT_PATH = "/fedizhelloworld";

    @AfterClass
    public static void cleanup() {
        SecurityTestUtil.cleanup();
    }


    private FedizContext loadConfig(String context) {
        try {
            FedizConfigurator configurator = new FedizConfigurator();
            final URL resource = Thread.currentThread().getContextClassLoader()
                    .getResource(CONFIG_FILE);
            File f = new File(resource.toURI());
            configurator.loadConfig(f);
            return configurator.getFedizContext(context);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    @org.junit.Test
    public void validateMetaDataWithAlias() throws ProcessingException, XMLSignatureException, XMLSecurityException {

        FedizContext config = loadConfig("ROOT");

        FedizProcessor wfProc = new FederationProcessorImpl();
        Document doc = wfProc.getMetaData(null, config);
        Assert.assertNotNull(doc);

        Node signatureNode = doc.getElementsByTagName("Signature").item(0);
        Assert.assertNotNull(signatureNode);

        doc.getDocumentElement().setIdAttributeNS(null, "ID", true);

        try {
            DOMUtils.writeXml(doc, System.out);
        } catch (TransformerException e) {
            fail("Exception not expected: " + e.getMessage());
        }

        // Validate the signature
        XMLSignature signature = new XMLSignature((Element)signatureNode, "");
        KeyInfo ki = signature.getKeyInfo();
        Assert.assertNotNull(ki);
        Assert.assertNotNull(ki.getX509Certificate());

        Assert.assertTrue(signature.checkSignatureValue(ki.getX509Certificate()));
    }

    @org.junit.Test
    public void validateMetaDataNoAlias() throws ProcessingException {

        try {
            FedizContext config = loadConfig("ROOT_NO_KEY");

            HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
            EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL));
            EasyMock.expect(req.getContextPath()).andReturn(CONTEXT_PATH);
            EasyMock.replay(req);

            FedizProcessor wfProc = new FederationProcessorImpl();
            Document doc = wfProc.getMetaData(req, config);
            Assert.assertNull(doc);
            fail("Failure expected as signing store contains more than one certificate");
        } catch (ProcessingException ex) {
            //Expected as signing store contains more than one certificate
        }
    }

    @org.junit.Test
    public void validateMetaDataNoSigningKey() throws ProcessingException {

        FedizContext config = loadConfig("ROOT_NO_SIGNINGKEY");

        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL)).times(2);
        EasyMock.expect(req.getContextPath()).andReturn(CONTEXT_PATH).times(2);
        EasyMock.replay(req);

        FedizProcessor wfProc = new FederationProcessorImpl();
        Document doc = wfProc.getMetaData(req, config);
        Assert.assertNotNull(doc);

        try {
            DOMUtils.writeXml(doc, System.out);
        } catch (TransformerException e) {
            fail("Exception not expected: " + e.getMessage());
        }
    }

}
