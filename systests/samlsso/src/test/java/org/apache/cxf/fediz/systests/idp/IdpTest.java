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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
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
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.xml.security.utils.Base64;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

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
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/" 
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest = 
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");
        signAuthnRequest(authnRequest);
        
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
        InputStream inputStream = new DeflateEncoderDecoder().inflateToken(deflatedToken);
        
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
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/" 
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest = 
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld-xyz", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");
        signAuthnRequest(authnRequest);
        
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
    
    @org.junit.Test
    public void testMissingDestination() throws Exception {
        OpenSAMLUtil.initSamlEngine();
        
        // Create SAML AuthnRequest
        Document doc = DOMUtils.createDocument();
        doc.appendChild(doc.createElement("root"));
        // Create the AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/" 
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest = 
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        signAuthnRequest(authnRequest);
        
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
            Assert.fail("Failure expected on no destination value");
        } catch (FailingHttpStatusCodeException ex) {
            // expected
        }
        
        webClient.close();
    }
    
    @org.junit.Test
    public void testUnsignedRequest() throws Exception {
        OpenSAMLUtil.initSamlEngine();
        
        // Create SAML AuthnRequest
        Document doc = DOMUtils.createDocument();
        doc.appendChild(doc.createElement("root"));
        // Create the AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/" 
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest = 
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");
        
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
            Assert.fail("Failure expected on an unsigned request");
        } catch (FailingHttpStatusCodeException ex) {
            Assert.assertEquals(ex.getStatusCode(), 400);
        }
        
        webClient.close();
    }
    
    @org.junit.Test
    public void testSeparateSignature() throws Exception {
        OpenSAMLUtil.initSamlEngine();
        
        // Create SAML AuthnRequest
        Document doc = DOMUtils.createDocument();
        doc.appendChild(doc.createElement("root"));
        // Create the AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/" 
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest = 
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");
        
        Element authnRequestElement = OpenSAMLUtil.toDom(authnRequest, doc);
        String authnRequestEncoded = encodeAuthnRequest(authnRequestElement);

        String urlEncodedRequest = URLEncoder.encode(authnRequestEncoded, "UTF-8");

        String relayState = UUID.randomUUID().toString();
        
        // Sign request
        Crypto crypto = CryptoFactory.getInstance("stsKeystoreA.properties");
        
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("realma");

        // Get the private key
        PrivateKey privateKey = crypto.getPrivateKey("realma", "realma");
        
        java.security.Signature signature = java.security.Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
       
        String requestToSign = SSOConstants.SAML_REQUEST + "=" + urlEncodedRequest;
        requestToSign += "&" + SSOConstants.RELAY_STATE + "=" + relayState;
        requestToSign += "&" + SSOConstants.SIG_ALG + "=" 
            + URLEncoder.encode(SSOConstants.RSA_SHA1, StandardCharsets.UTF_8.name());
        
        signature.update(requestToSign.getBytes(StandardCharsets.UTF_8));
        byte[] signBytes = signature.sign();
        
        String encodedSignature = Base64.encode(signBytes);
        
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml/up?";
        url += SSOConstants.RELAY_STATE + "=" + relayState;
        url += "&" + SSOConstants.SAML_REQUEST + "=" + urlEncodedRequest;
        url += "&" + SSOConstants.SIGNATURE + "=" + URLEncoder.encode(encodedSignature, StandardCharsets.UTF_8.name());

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
        InputStream inputStream = new DeflateEncoderDecoder().inflateToken(deflatedToken);
        
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
    public void testUnknownRACS() throws Exception {
        OpenSAMLUtil.initSamlEngine();
        
        // Create SAML AuthnRequest
        Document doc = DOMUtils.createDocument();
        doc.appendChild(doc.createElement("root"));
        // Create the AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/" 
            + getServletContextName() + "/insecure/fedservlet";
        AuthnRequest authnRequest = 
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");
        signAuthnRequest(authnRequest);
        
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
            Assert.fail("Failure expected on a bad RACS URL");
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
    
    private void signAuthnRequest(AuthnRequest authnRequest) throws Exception {
        Crypto crypto = CryptoFactory.getInstance("stsKeystoreA.properties");
        
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("realma");
        X509Certificate[] issuerCerts = crypto.getX509Certificates(cryptoType);

        String sigAlgo = SSOConstants.RSA_SHA1;
        
        // Get the private key
        PrivateKey privateKey = crypto.getPrivateKey("realma", "realma");
        
        // Create the signature
        Signature signature = OpenSAMLUtil.buildSignature();
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signature.setSignatureAlgorithm(sigAlgo);
        
        BasicX509Credential signingCredential = new BasicX509Credential(issuerCerts[0], privateKey);

        signature.setSigningCredential(signingCredential);

        X509KeyInfoGeneratorFactory kiFactory = new X509KeyInfoGeneratorFactory();
        kiFactory.setEmitEntityCertificate(true);
        
        try {
            KeyInfo keyInfo = kiFactory.newInstance().generate(signingCredential);
            signature.setKeyInfo(keyInfo);
        } catch (org.opensaml.security.SecurityException ex) {
            throw new Exception(
                    "Error generating KeyInfo from signing credential", ex);
        }
        
        SignableSAMLObject signableObject = (SignableSAMLObject) authnRequest;
        signableObject.setSignature(signature);
        signableObject.releaseDOM();
        signableObject.releaseChildrenDOM(true);
        
    }
}
