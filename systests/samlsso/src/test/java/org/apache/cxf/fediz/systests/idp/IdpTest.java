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

package org.apache.cxf.fediz.systests.idp;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URLEncoder;
import java.util.UUID;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.cxf.rs.security.saml.DeflateEncoderDecoder;
import org.apache.cxf.rs.security.saml.sso.DefaultAuthnRequestBuilder;
import org.apache.cxf.rs.security.saml.sso.SSOConstants;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.AuthnRequest;

/**
 * Some tests invoking directly on the IdP for SAML SSO
 */
public class IdpTest {

    static String idpHttpsPort;
    static String rpHttpsPort;

    private static Tomcat idpServer;

    @BeforeClass
    public static void init() {
        System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
        System.setProperty("org.apache.commons.logging.simplelog.showdatetime", "true");
        System.setProperty("org.apache.commons.logging.simplelog.log.httpclient.wire", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.commons.httpclient", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.springframework.webflow", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.springframework.security.web", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.cxf.fediz", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.cxf", "info");

        idpHttpsPort = System.getProperty("idp.https.port");
        Assert.assertNotNull("Property 'idp.https.port' null", idpHttpsPort);
        rpHttpsPort = System.getProperty("rp.https.port");
        Assert.assertNotNull("Property 'rp.https.port' null", rpHttpsPort);

        initIdp();

        WSSConfig.init();
    }

    private static void initIdp() {
        try {
            idpServer = new Tomcat();
            idpServer.setPort(0);
            String currentDir = new File(".").getCanonicalPath();
            idpServer.setBaseDir(currentDir + File.separator + "target");

            idpServer.getHost().setAppBase("tomcat/idp/webapps");
            idpServer.getHost().setAutoDeploy(true);
            idpServer.getHost().setDeployOnStartup(true);

            Connector httpsConnector = new Connector();
            httpsConnector.setPort(Integer.parseInt(idpHttpsPort));
            httpsConnector.setSecure(true);
            httpsConnector.setScheme("https");
            //httpsConnector.setAttribute("keyAlias", keyAlias);
            httpsConnector.setAttribute("keystorePass", "tompass");
            httpsConnector.setAttribute("keystoreFile", "test-classes/server.jks");
            httpsConnector.setAttribute("truststorePass", "tompass");
            httpsConnector.setAttribute("truststoreFile", "test-classes/server.jks");
            httpsConnector.setAttribute("clientAuth", "want");
            // httpsConnector.setAttribute("clientAuth", "false");
            httpsConnector.setAttribute("sslProtocol", "TLS");
            httpsConnector.setAttribute("SSLEnabled", true);

            idpServer.getService().addConnector(httpsConnector);

            idpServer.addWebapp("/fediz-idp-sts", "fediz-idp-sts");
            idpServer.addWebapp("/fediz-idp", "fediz-idp");

            idpServer.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @AfterClass
    public static void cleanup() {
        try {
            if (idpServer.getServer() != null
                && idpServer.getServer().getState() != LifecycleState.DESTROYED) {
                if (idpServer.getServer().getState() != LifecycleState.STOPPED) {
                    idpServer.stop();
                }
                idpServer.destroy();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String getIdpHttpsPort() {
        return idpHttpsPort;
    }

    public String getRpHttpsPort() {
        return rpHttpsPort;
    }

    public String getServletContextName() {
        return "fedizhelloworld";
    }
    
    @org.junit.Test
    public void testSuccessfulInvokeOnIdP() throws Exception {
        OpenSAMLUtil.initSamlEngine();
        
        // Create SAML AuthnRequest
        Document doc = DOMUtils.createDocument();
        doc.appendChild(doc.createElement("root"));
        // Create the AuthnRequest
        String consumerURL = "https://localhost/acsa";
        AuthnRequest authnRequest = 
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        
        Element authnRequestElement = OpenSAMLUtil.toDom(authnRequest, doc);
        String authnRequestEncoded = encodeAuthnRequest(authnRequestElement);

        String urlEncodedRequest = URLEncoder.encode(authnRequestEncoded, "UTF-8");

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?";
        url += SSOConstants.RELAY_STATE + "=" + relayState;
        url += "&" + SSOConstants.SAML_REQUEST + "=" + urlEncodedRequest;

        String user = "alice";
        String password = "ecila";

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assert.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());
        
        // Parse the form to get the token (SAMLResponse)
        DomNodeList<DomElement> results = idpPage.getElementsByTagName("input");

        String samlResponse = null;
        boolean foundRelayState = false;
        for (DomElement result : results) {
            if ("SAMLResponse".equals(result.getAttributeNS(null, "name"))) {
                samlResponse = result.getAttributeNS(null, "value");
            } else if ("RelayState".equals(result.getAttributeNS(null, "name"))) {
                foundRelayState = true;
                Assert.assertEquals(result.getAttributeNS(null, "value"), relayState);
            }
        }

        Assert.assertNotNull(samlResponse);
        Assert.assertTrue(foundRelayState);
        
        // Check the "action"
        DomNodeList<DomElement> formResults = idpPage.getElementsByTagName("form");
        Assert.assertFalse(formResults.isEmpty());
        
        DomElement formResult = formResults.get(0);
        String action = formResult.getAttributeNS(null, "action");
        Assert.assertTrue(action.equals(consumerURL));
        
        // Decode + verify response
        byte[] deflatedToken = Base64Utility.decode(samlResponse);
        InputStream inputStream = new ByteArrayInputStream(deflatedToken);
        
        Document responseDoc = StaxUtils.read(new InputStreamReader(inputStream, "UTF-8"));
        
        XMLObject responseObject = OpenSAMLUtil.fromDom(responseDoc.getDocumentElement());
        Assert.assertTrue(responseObject instanceof org.opensaml.saml.saml2.core.Response);
        
        org.opensaml.saml.saml2.core.Response samlResponseObject = 
            (org.opensaml.saml.saml2.core.Response)responseObject;
        Assert.assertTrue(authnRequest.getID().equals(samlResponseObject.getInResponseTo()));
        
        // Check claims
        String parsedResponse = DOM2Writer.nodeToString(responseDoc);
        String claim = ClaimTypes.FIRSTNAME.toString();
        Assert.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.LASTNAME.toString();
        Assert.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assert.assertTrue(parsedResponse.contains(claim));

        webClient.close();
    }
    
    @org.junit.Test
    public void testBadIssuer() throws Exception {
        OpenSAMLUtil.initSamlEngine();
        
        // Create SAML AuthnRequest
        Document doc = DOMUtils.createDocument();
        doc.appendChild(doc.createElement("root"));
        // Create the AuthnRequest
        AuthnRequest authnRequest = 
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld-xyz", "https://localhost/acsa"
            );
        
        Element authnRequestElement = OpenSAMLUtil.toDom(authnRequest, doc);
        String authnRequestEncoded = encodeAuthnRequest(authnRequestElement);

        String urlEncodedRequest = URLEncoder.encode(authnRequestEncoded, "UTF-8");

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?";
        url += SSOConstants.RELAY_STATE + "=" + relayState;
        url += "&" + SSOConstants.SAML_REQUEST + "=" + urlEncodedRequest;

        String user = "alice";
        String password = "ecila";

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);
        try {
            webClient.getPage(url);
            Assert.fail("Failure expected on a bad issuer value");
        } catch (FailingHttpStatusCodeException ex) {
            Assert.assertEquals(ex.getStatusCode(), 400);
        }
        
        webClient.close();
    }
    
    private String encodeAuthnRequest(Element authnRequest) throws IOException {
        String requestMessage = DOM2Writer.nodeToString(authnRequest);
        
        DeflateEncoderDecoder encoder = new DeflateEncoderDecoder();
        byte[] deflatedBytes = encoder.deflateToken(requestMessage.getBytes("UTF-8"));

        return Base64Utility.encode(deflatedBytes);
    }
}
