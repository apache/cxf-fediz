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

package org.apache.cxf.fediz.systests.samlsso;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLEncoder;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;

import javax.servlet.ServletException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import com.gargoylesoftware.htmlunit.CookieManager;
import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.HttpMethod;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;
import com.gargoylesoftware.htmlunit.util.NameValuePair;
import com.gargoylesoftware.htmlunit.xml.XmlPage;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.cxf.rs.security.saml.DeflateEncoderDecoder;
import org.apache.cxf.rs.security.saml.sso.DefaultAuthnRequestBuilder;
import org.apache.cxf.rs.security.saml.sso.SSOConstants;
import org.apache.cxf.rs.security.saml.sso.SamlpRequestComponentBuilder;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Some tests invoking directly on the IdP for SAML SSO
 */
public class IdpTest {

    private static final String IDP_HTTPS_PORT = System.getProperty("idp.https.port");
    private static final String RP_HTTPS_PORT = System.getProperty("rp.https.port");

    private static final String  USER = "alice";
    private static final String  PWD = "ecila";

    private static Tomcat idpServer;

    @BeforeAll
    public static void init() throws Exception {
        Assertions.assertNotNull("Property 'idp.https.port' null", IDP_HTTPS_PORT);
        Assertions.assertNotNull("Property 'rp.https.port' null", RP_HTTPS_PORT);

        idpServer = startServer(IDP_HTTPS_PORT);

        WSSConfig.init();
    }

    private static Tomcat startServer(String port)
        throws ServletException, LifecycleException, IOException {
        Tomcat server = new Tomcat();
        server.setPort(0);
        String currentDir = new File(".").getCanonicalPath();
        String baseDir = currentDir + File.separator + "target";
        server.setBaseDir(baseDir);

        server.getHost().setAppBase("tomcat/idp/webapps");
        server.getHost().setAutoDeploy(true);
        server.getHost().setDeployOnStartup(true);

        Connector httpsConnector = new Connector();
        httpsConnector.setPort(Integer.parseInt(port));
        httpsConnector.setSecure(true);
        httpsConnector.setScheme("https");
        httpsConnector.setProperty("keyAlias", "mytomidpkey");
        httpsConnector.setProperty("keystorePass", "tompass");
        httpsConnector.setProperty("keystoreFile", "test-classes/server.jks");
        httpsConnector.setProperty("truststorePass", "tompass");
        httpsConnector.setProperty("truststoreFile", "test-classes/server.jks");
        httpsConnector.setProperty("clientAuth", "want");
        // httpsConnector.setProperty("clientAuth", "false");
        httpsConnector.setProperty("sslProtocol", "TLS");
        httpsConnector.setProperty("SSLEnabled", "true");

        server.getService().addConnector(httpsConnector);

        File stsWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp-sts");
        server.addWebapp("/fediz-idp-sts", stsWebapp.getAbsolutePath());

        File idpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp");
        server.addWebapp("/fediz-idp", idpWebapp.getAbsolutePath());

        server.start();

        return server;
    }

    @AfterAll
    public static void cleanup() {
        shutdownServer(idpServer);
    }

    private static void shutdownServer(Tomcat server) {
        try {
            if (server != null && server.getServer() != null
                && server.getServer().getState() != LifecycleState.DESTROYED) {
                if (server.getServer().getState() != LifecycleState.STOPPED) {
                    server.stop();
                }
                server.destroy();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static String getIdpHttpsPort() {
        return IDP_HTTPS_PORT;
    }

    static String getRpHttpsPort() {
        return RP_HTTPS_PORT;
    }

    static String getServletContextName() {
        return "fedizhelloworld";
    }

    //
    // Successful tests
    //
    /*
    @org.junit.jupiter.api.Test
    public void testBrowser() throws Exception {
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

        String urlEncodedRequest = URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?";
        url += SSOConstants.RELAY_STATE + "=" + relayState;
        url += "&" + SSOConstants.SAML_REQUEST + "=" + urlEncodedRequest;

        System.out.println("URL: " + url);

        Thread.sleep(60 * 1000);

    }
    */

    @Test
    public void testIdPMetadata() throws Exception {
        String url = "https://localhost:" + getIdpHttpsPort()
            + "/fediz-idp/metadata?protocol=saml";

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getOptions().setSSLClientCertificate(
            this.getClass().getClassLoader().getResource("client.jks"), "storepass", "jks");

        final XmlPage rpPage = webClient.getPage(url);
        final String xmlContent = rpPage.asXml();
        Assertions.assertTrue(xmlContent.startsWith("<md:EntityDescriptor"));

        // Now validate the Signature
        Document doc = rpPage.getXmlDocument();

        doc.getDocumentElement().setIdAttributeNS(null, "ID", true);

        Node signatureNode =
            DOMUtils.getChild(doc.getDocumentElement(), "Signature");
        Assertions.assertNotNull(signatureNode);

        XMLSignature signature = new XMLSignature((Element)signatureNode, "");
        org.apache.xml.security.keys.KeyInfo ki = signature.getKeyInfo();
        Assertions.assertNotNull(ki);
        Assertions.assertNotNull(ki.getX509Certificate());

        Assertions.assertTrue(signature.checkSignatureValue(ki.getX509Certificate()));

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testSuccessfulInvokeOnIdP() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");
        signAuthnRequest(authnRequest);

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assertions.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        // Check claims
        String parsedResponse = DOM2Writer.nodeToString(samlResponse.getDOM().getOwnerDocument());
        String claim = ClaimTypes.FIRSTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.LASTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testSuccessfulInvokeOnIdPUsingPOST() throws Exception {
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
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml/up");
        signAuthnRequest(authnRequest);

        Element authnRequestElement = OpenSAMLUtil.toDom(authnRequest, doc);

        // Don't inflate the token...
        String requestMessage = DOM2Writer.nodeToString(authnRequestElement);
        String authnRequestEncoded = Base64Utility.encode(requestMessage.getBytes(UTF_8.name()));

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml/up";

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);

        WebRequest request = new WebRequest(new URL(url), HttpMethod.POST);

        request.setRequestParameters(new ArrayList<NameValuePair>());
        request.getRequestParameters().add(new NameValuePair(SSOConstants.RELAY_STATE, relayState));
        request.getRequestParameters().add(new NameValuePair(SSOConstants.SAML_REQUEST, authnRequestEncoded));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(request);

        webClient.getOptions().setJavaScriptEnabled(true);
        Assertions.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        // Check claims
        String parsedResponse = DOM2Writer.nodeToString(samlResponse.getDOM().getOwnerDocument());
        String claim = ClaimTypes.FIRSTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.LASTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testSeparateSignature() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String urlEncodedRequest = URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        String relayState = UUID.randomUUID().toString();

        // Sign request
        Crypto crypto = CryptoFactory.getInstance("stsKeystoreA.properties");

        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("realma");

        // Get the private key
        PrivateKey privateKey = crypto.getPrivateKey("realma", "realma");

        java.security.Signature signature = java.security.Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);

        String requestToSign = SSOConstants.SAML_REQUEST + "=" + urlEncodedRequest
                + "&" + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SIG_ALG + "=" + URLEncoder.encode(SSOConstants.RSA_SHA1, UTF_8.name());

        signature.update(requestToSign.getBytes(UTF_8));
        byte[] signBytes = signature.sign();

        String encodedSignature = Base64.getEncoder().encodeToString(signBytes);

        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml/up?"
            + SSOConstants.RELAY_STATE + "=" + relayState
            + "&" + SSOConstants.SAML_REQUEST + "=" + urlEncodedRequest
            + "&" + SSOConstants.SIGNATURE + "=" + URLEncoder.encode(encodedSignature, UTF_8.name());

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assertions.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        // Check claims
        String parsedResponse = DOM2Writer.nodeToString(samlResponse.getDOM().getOwnerDocument());
        String claim = ClaimTypes.FIRSTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.LASTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testSeparateSignatureRSASHA256() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String urlEncodedRequest = URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        String relayState = UUID.randomUUID().toString();

        // Sign request
        Crypto crypto = CryptoFactory.getInstance("stsKeystoreA.properties");

        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("realma");

        // Get the private key
        PrivateKey privateKey = crypto.getPrivateKey("realma", "realma");

        java.security.Signature signature = java.security.Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);

        String encodedSignatureAlgorithm =
                URLEncoder.encode("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", UTF_8.name());
        String requestToSign = SSOConstants.SAML_REQUEST + "=" + urlEncodedRequest
                + "&" + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SIG_ALG + "=" + encodedSignatureAlgorithm;

        signature.update(requestToSign.getBytes(UTF_8));
        byte[] signBytes = signature.sign();

        String encodedSignature = Base64.getEncoder().encodeToString(signBytes);

        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml/up?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + urlEncodedRequest
                + "&" + SSOConstants.SIG_ALG + "=" + encodedSignatureAlgorithm
                + "&" + SSOConstants.SIGNATURE + "=" + URLEncoder.encode(encodedSignature, UTF_8.name());

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assertions.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        // Check claims
        String parsedResponse = DOM2Writer.nodeToString(samlResponse.getDOM().getOwnerDocument());
        String claim = ClaimTypes.FIRSTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.LASTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testSuccessfulSSOInvokeOnIdP() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");
        signAuthnRequest(authnRequest);

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.addRequestHeader("Authorization", "Basic "
            + Base64.getEncoder().encodeToString((USER + ":" + PWD).getBytes(UTF_8)));

        //
        // First invocation
        //

        webClient.getOptions().setJavaScriptEnabled(false);
        HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assertions.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        // Check claims
        String parsedResponse = DOM2Writer.nodeToString(samlResponse.getDOM().getOwnerDocument());
        String claim = ClaimTypes.FIRSTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.LASTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));

        //
        // Second invocation - change the credentials to make sure the session is set up correctly
        //

        webClient.removeRequestHeader("Authorization");
        webClient.addRequestHeader("Authorization", "Basic "
            + Base64.getEncoder().encodeToString(("mallory" + ":" + PWD).getBytes(UTF_8)));

        webClient.getOptions().setJavaScriptEnabled(false);
        idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assertions.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        samlResponse = parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        expected = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        // Check claims
        parsedResponse = DOM2Writer.nodeToString(samlResponse.getDOM().getOwnerDocument());
        claim = ClaimTypes.FIRSTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.LASTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testSuccessfulSSOInvokeOnIdPWithForceAuthn() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setForceAuthn(Boolean.TRUE);
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");
        signAuthnRequest(authnRequest);

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        final WebClient webClient = new WebClient();
        CookieManager cookieManager = new CookieManager();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        //
        // First invocation
        //

        webClient.getOptions().setJavaScriptEnabled(false);
        HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assertions.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        // Check claims
        String parsedResponse = DOM2Writer.nodeToString(samlResponse.getDOM().getOwnerDocument());
        String claim = ClaimTypes.FIRSTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.LASTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));

        //
        // Second invocation
        //

        webClient.getOptions().setJavaScriptEnabled(false);
        idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assertions.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        samlResponse = parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        expected = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        // Check claims
        parsedResponse = DOM2Writer.nodeToString(samlResponse.getDOM().getOwnerDocument());
        claim = ClaimTypes.FIRSTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.LASTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));

        webClient.close();

        //
        // Third invocation - create a new WebClient with no credentials (but with the same CookieManager)
        // ...this should fail
        //

        WebClient newWebClient = new WebClient();
        newWebClient.setCookieManager(cookieManager);
        newWebClient.getOptions().setUseInsecureSSL(true);
        newWebClient.getOptions().setJavaScriptEnabled(false);

        try {
            newWebClient.getPage(url);
            Assertions.fail("Failure expected on no credentials");
        }  catch (FailingHttpStatusCodeException ex) {
            Assertions.assertEquals(ex.getStatusCode(), 401);
        }

        newWebClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testSuccessfulSSOInvokeOnIdPWithForceAuthnSeparateSignature() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setForceAuthn(Boolean.TRUE);
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String urlEncodedRequest = URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        String relayState = UUID.randomUUID().toString();

        // Sign request
        Crypto crypto = CryptoFactory.getInstance("stsKeystoreA.properties");

        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("realma");

        // Get the private key
        PrivateKey privateKey = crypto.getPrivateKey("realma", "realma");

        java.security.Signature signature = java.security.Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);

        String requestToSign = SSOConstants.SAML_REQUEST + "=" + urlEncodedRequest
                + "&" + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SIG_ALG + "=" + URLEncoder.encode(SSOConstants.RSA_SHA1, UTF_8.name());

        signature.update(requestToSign.getBytes(UTF_8));
        byte[] signBytes = signature.sign();

        String encodedSignature = Base64.getEncoder().encodeToString(signBytes);

        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml/up?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + urlEncodedRequest
                + "&" + SSOConstants.SIGNATURE + "=" + URLEncoder.encode(encodedSignature, UTF_8.name());

        final WebClient webClient = new WebClient();
        CookieManager cookieManager = new CookieManager();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        //
        // First invocation
        //

        webClient.getOptions().setJavaScriptEnabled(false);
        HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assertions.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        // Check claims
        String parsedResponse = DOM2Writer.nodeToString(samlResponse.getDOM().getOwnerDocument());
        String claim = ClaimTypes.FIRSTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.LASTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));

        //
        // Second invocation
        //

        webClient.getOptions().setJavaScriptEnabled(false);
        idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assertions.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        samlResponse = parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        expected = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        // Check claims
        parsedResponse = DOM2Writer.nodeToString(samlResponse.getDOM().getOwnerDocument());
        claim = ClaimTypes.FIRSTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.LASTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));

        webClient.close();

        //
        // Third invocation - create a new WebClient with no credentials (but with the same CookieManager)
        // ...this should fail
        //

        WebClient newWebClient = new WebClient();
        newWebClient.setCookieManager(cookieManager);
        newWebClient.getOptions().setUseInsecureSSL(true);
        newWebClient.getOptions().setJavaScriptEnabled(false);

        try {
            newWebClient.getPage(url);
            Assertions.fail("Failure expected on no credentials");
        }  catch (FailingHttpStatusCodeException ex) {
            Assertions.assertEquals(ex.getStatusCode(), 401);
        }

        newWebClient.close();
    }

    //
    // Negative tests
    //

    @org.junit.jupiter.api.Test
    public void testBadIssuer() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld-xyz", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");
        signAuthnRequest(authnRequest);

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testNoIssuer() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, null, consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");
        signAuthnRequest(authnRequest);

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testBadIssuerFormat() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";

        String issuerId = "urn:org:apache:cxf:fediz:fedizhelloworld";
        Issuer issuer =
            SamlpRequestComponentBuilder.createIssuer(issuerId);
        issuer.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");

        String nameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
        NameIDPolicy nameIDPolicy =
            SamlpRequestComponentBuilder.createNameIDPolicy(true, nameIDFormat, issuerId);

        AuthnContextClassRef authnCtxClassRef =
            SamlpRequestComponentBuilder.createAuthnCtxClassRef(
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            );
        RequestedAuthnContext authnCtx =
            SamlpRequestComponentBuilder.createRequestedAuthnCtxPolicy(
                AuthnContextComparisonTypeEnumeration.EXACT,
                Collections.singletonList(authnCtxClassRef), null
            );

        String protocolBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
        AuthnRequest authnRequest = SamlpRequestComponentBuilder.createAuthnRequest(
                consumerURL,
                false,
                false,
                protocolBinding,
                SAMLVersion.VERSION_20,
                issuer,
                nameIDPolicy,
                authnCtx
        );

        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");
        signAuthnRequest(authnRequest);

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testMissingDestination() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        signAuthnRequest(authnRequest);

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testMissingRelayState() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");
        signAuthnRequest(authnRequest);

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?"
                + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        try {
            webClient.getPage(url);
            Assertions.fail("Failure expected on not sending the RelayState");
        }  catch (FailingHttpStatusCodeException ex) {
            Assertions.assertEquals(ex.getStatusCode(), 400);
        }

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testUnsignedRequest() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testEmptySeparateSignature() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String relayState = UUID.randomUUID().toString();

        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml/up?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(authnRequestEncoded, UTF_8.name())
                + "&" + SSOConstants.SIGNATURE + "=";

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testBase64DecodingErrorSeparateSignature() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String urlEncodedRequest = URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        String relayState = UUID.randomUUID().toString();

        // Sign request
        Crypto crypto = CryptoFactory.getInstance("stsKeystoreA.properties");

        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("realma");

        // Get the private key
        PrivateKey privateKey = crypto.getPrivateKey("realma", "realma");

        java.security.Signature signature = java.security.Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);

        String requestToSign = SSOConstants.SAML_REQUEST + "=" + urlEncodedRequest
                + "&" + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SIG_ALG + "=" + URLEncoder.encode(SSOConstants.RSA_SHA1, UTF_8.name());

        signature.update(requestToSign.getBytes(UTF_8));
        byte[] signBytes = signature.sign();

        String encodedSignature = Base64.getEncoder().encodeToString(signBytes);

        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml/up?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + urlEncodedRequest
                + "&" + SSOConstants.SIGNATURE + "=" + URLEncoder.encode(encodedSignature, UTF_8.name()) + "-xyz";

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testChangedSeparateSignature() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String urlEncodedRequest = URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        String relayState = UUID.randomUUID().toString();

        // Sign request
        Crypto crypto = CryptoFactory.getInstance("stsKeystoreA.properties");

        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("realma");

        // Get the private key
        PrivateKey privateKey = crypto.getPrivateKey("realma", "realma");

        java.security.Signature signature = java.security.Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);

        String requestToSign = SSOConstants.SAML_REQUEST + "=" + urlEncodedRequest
                + "&" + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SIG_ALG + "=" + URLEncoder.encode(SSOConstants.RSA_SHA1, UTF_8.name());

        signature.update(requestToSign.getBytes(UTF_8));
        byte[] signBytes = signature.sign();
        if (signBytes[1] != (byte)1) {
            signBytes[1] = (byte)1;
        } else {
            signBytes[1] = (byte)2;
        }

        String encodedSignature = Base64.getEncoder().encodeToString(signBytes);

        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml/up?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + urlEncodedRequest
                + "&" + SSOConstants.SIGNATURE + "=" + URLEncoder.encode(encodedSignature, UTF_8.name());

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testSeparateSignatureWrongSignedContent() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String urlEncodedRequest = URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        String relayState = UUID.randomUUID().toString();

        // Sign request
        Crypto crypto = CryptoFactory.getInstance("stsKeystoreA.properties");

        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("realma");

        // Get the private key
        PrivateKey privateKey = crypto.getPrivateKey("realma", "realma");

        java.security.Signature signature = java.security.Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);

        String requestToSign = SSOConstants.SAML_REQUEST + "=" + urlEncodedRequest
                + "&" + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SIG_ALG + "=" + URLEncoder.encode(SSOConstants.RSA_SHA1, UTF_8.name()) + "asf=xyz";

        signature.update(requestToSign.getBytes(UTF_8));
        byte[] signBytes = signature.sign();

        String encodedSignature = Base64.getEncoder().encodeToString(signBytes);

        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml/up?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + urlEncodedRequest
                + "&" + SSOConstants.SIGNATURE + "=" + URLEncoder.encode(encodedSignature, UTF_8.name());

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testUnknownRACS() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/insecure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");
        signAuthnRequest(authnRequest);

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testProblemWithParsingRequest() throws Exception {
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

        // Don't inflate the token...
        String requestMessage = DOM2Writer.nodeToString(authnRequestElement);
        String authnRequestEncoded = Base64Utility.encode(requestMessage.getBytes(UTF_8));

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        try {
            webClient.getPage(url);
            Assertions.fail("Failure expected on parsing the request in the IdP");
        }  catch (FailingHttpStatusCodeException ex) {
            Assertions.assertEquals(ex.getStatusCode(), 400);
        }

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testForceAuthnWrongCredentials() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setForceAuthn(Boolean.TRUE);
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");
        signAuthnRequest(authnRequest);

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.addRequestHeader("Authorization", "Basic "
            + Base64.getEncoder().encodeToString((USER + ":" + PWD).getBytes(UTF_8)));

        //
        // First invocation
        //

        webClient.getOptions().setJavaScriptEnabled(false);
        HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assertions.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());

        // Check claims
        String parsedResponse = DOM2Writer.nodeToString(samlResponse.getDOM().getOwnerDocument());
        String claim = ClaimTypes.FIRSTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.LASTNAME.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assertions.assertTrue(parsedResponse.contains(claim));

        //
        // Second invocation - change the credentials, this should fail
        //

        webClient.removeRequestHeader("Authorization");
        webClient.addRequestHeader("Authorization", "Basic "
            + Base64.getEncoder().encodeToString(("mallory" + ":" + PWD).getBytes(UTF_8)));

        webClient.getOptions().setJavaScriptEnabled(false);
        try {
            webClient.getPage(url);
            Assertions.fail("Authentication failure expected");
        }  catch (FailingHttpStatusCodeException ex) {
            Assertions.assertEquals(ex.getStatusCode(), 401);
        }

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testIdPLogout() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // 1. First let's login to the IdP

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");
        signAuthnRequest(authnRequest);

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        CookieManager cookieManager = new CookieManager();

        WebClient webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assertions.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());
        NameID nameID = samlResponse.getAssertions().get(0).getSubject().getNameID();
        Assertions.assertNotNull(nameID);
        nameID.detach();

        webClient.close();

        // 2. now we logout from IdP

        // Create SAML LogoutRequest
        Issuer issuer = SamlpRequestComponentBuilder.createIssuer("urn:org:apache:cxf:fediz:fedizhelloworld");
        String destination = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml";
        LogoutRequest logoutRequest =
            SamlpRequestComponentBuilder.createLogoutRequest(SAMLVersion.VERSION_20, issuer, destination,
                                                             null, null, null, nameID);

        signAuthnRequest(logoutRequest);

        String logoutRequestEncoded = encodeAuthnRequest(logoutRequest);

        relayState = UUID.randomUUID().toString();
        String logoutURL = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(logoutRequestEncoded, UTF_8.name());

        webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        idpPage = webClient.getPage(logoutURL);
        webClient.getOptions().setJavaScriptEnabled(true);

        Assertions.assertEquals("IDP SignOut Confirmation Response Page", idpPage.getTitleText());

        HtmlForm form = idpPage.getFormByName("signoutconfirmationresponseform");
        HtmlSubmitInput button = form.getInputByName("_eventId_submit");
        HtmlPage signoutPage = button.click();

        // Check Response
        HtmlForm responseForm = signoutPage.getFormByName("samlsignoutresponseform");
        String logoutResponseURL = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/logout";
        Assertions.assertEquals(logoutResponseURL, responseForm.getActionAttribute());
        String responseValue = responseForm.getInputByName("SAMLResponse").getAttributeNS(null, "value");
        Assertions.assertNotNull(responseValue);
        String receivedRelayState = responseForm.getInputByName("RelayState").getAttributeNS(null, "value");
        Assertions.assertEquals(relayState, receivedRelayState);

        byte[] deflatedToken = Base64Utility.decode(responseValue);
        InputStream tokenStream = new ByteArrayInputStream(deflatedToken);
        Document responseDoc = StaxUtils.read(new InputStreamReader(tokenStream, UTF_8));

        LogoutResponse logoutResponse = (LogoutResponse)OpenSAMLUtil.fromDom(responseDoc.getDocumentElement());
        Assertions.assertNotNull(logoutResponse);
        Assertions.assertEquals(logoutResponseURL, logoutResponse.getDestination());
        String expectedIssuer = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml";
        Assertions.assertEquals(expectedIssuer, logoutResponse.getIssuer().getValue());
        String success = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Assertions.assertEquals(success, logoutResponse.getStatus().getStatusCode().getValue());

        Assertions.assertNotNull(logoutResponse.getSignature());

        webClient.close();

        // 3. now we try to access the idp without authentication but with the existing cookies
        // to see if we are really logged out
        webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
        idpPage = webClient.getPage(url);

        Assertions.assertEquals(401, idpPage.getWebResponse().getStatusCode());

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testIdpLogoutRequestExpired() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // 1. First let's login to the IdP

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");
        signAuthnRequest(authnRequest);

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        CookieManager cookieManager = new CookieManager();

        WebClient webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assertions.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());
        NameID nameID = samlResponse.getAssertions().get(0).getSubject().getNameID();
        Assertions.assertNotNull(nameID);
        nameID.detach();

        webClient.close();

        // 2. now we logout from IdP

        // Create SAML LogoutRequest
        Issuer issuer = SamlpRequestComponentBuilder.createIssuer("urn:org:apache:cxf:fediz:fedizhelloworld");
        String destination = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml";
        Date now = new Date();
        now.setTime(now.getTime() - (60L * 1000L));
        LogoutRequest logoutRequest =
            SamlpRequestComponentBuilder.createLogoutRequest(SAMLVersion.VERSION_20, issuer, destination,
                                                             null, now, null, nameID);

        signAuthnRequest(logoutRequest);

        String logoutRequestEncoded = encodeAuthnRequest(logoutRequest);

        relayState = UUID.randomUUID().toString();
        String logoutURL = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(logoutRequestEncoded, UTF_8.name());

        webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        idpPage = webClient.getPage(logoutURL);
        webClient.getOptions().setJavaScriptEnabled(true);

        // Check Response
        HtmlForm responseForm = idpPage.getFormByName("samlsignoutresponseform");
        String logoutResponseURL = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/logout";
        Assertions.assertEquals(logoutResponseURL, responseForm.getActionAttribute());
        String responseValue = responseForm.getInputByName("SAMLResponse").getAttributeNS(null, "value");
        Assertions.assertNotNull(responseValue);
        String receivedRelayState = responseForm.getInputByName("RelayState").getAttributeNS(null, "value");
        Assertions.assertEquals(relayState, receivedRelayState);

        byte[] deflatedToken = Base64Utility.decode(responseValue);
        InputStream tokenStream = new ByteArrayInputStream(deflatedToken);
        Document responseDoc = StaxUtils.read(new InputStreamReader(tokenStream, UTF_8));

        LogoutResponse logoutResponse = (LogoutResponse)OpenSAMLUtil.fromDom(responseDoc.getDocumentElement());
        Assertions.assertNotNull(logoutResponse);
        Assertions.assertEquals(logoutResponseURL, logoutResponse.getDestination());
        String expectedIssuer = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml";
        Assertions.assertEquals(expectedIssuer, logoutResponse.getIssuer().getValue());
        String success = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        Assertions.assertEquals(success, logoutResponse.getStatus().getStatusCode().getValue());

        Assertions.assertNotNull(logoutResponse.getSignature());
        webClient.close();

        // 3. now we try to access the idp without authentication but with the existing cookies
        // to see if we are really logged out - we should still be logged in as our LogoutRequest was expired
        webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
        idpPage = webClient.getPage(url);

        Assertions.assertEquals(200, idpPage.getWebResponse().getStatusCode());

        webClient.close();
    }

    @org.junit.jupiter.api.Test
    public void testIdpLogoutCancelled() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // 1. First let's login to the IdP

        // Create SAML AuthnRequest
        String consumerURL = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        AuthnRequest authnRequest =
            new DefaultAuthnRequestBuilder().createAuthnRequest(
                null, "urn:org:apache:cxf:fediz:fedizhelloworld", consumerURL
            );
        authnRequest.setDestination("https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml");
        signAuthnRequest(authnRequest);

        String authnRequestEncoded = encodeAuthnRequest(authnRequest);

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?"
                + SSOConstants.RELAY_STATE + "=" + relayState
                + "&" + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(authnRequestEncoded, UTF_8.name());

        CookieManager cookieManager = new CookieManager();

        WebClient webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assertions.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        org.opensaml.saml.saml2.core.Response samlResponse =
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Assertions.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());
        NameID nameID = samlResponse.getAssertions().get(0).getSubject().getNameID();
        Assertions.assertNotNull(nameID);
        nameID.detach();

        webClient.close();

        // 2. now we logout from IdP - but cancel the logout

        // Create SAML LogoutRequest
        Issuer issuer = SamlpRequestComponentBuilder.createIssuer("urn:org:apache:cxf:fediz:fedizhelloworld");
        String destination = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml";
        LogoutRequest logoutRequest =
            SamlpRequestComponentBuilder.createLogoutRequest(SAMLVersion.VERSION_20, issuer, destination,
                                                             null, null, null, nameID);

        signAuthnRequest(logoutRequest);

        String logoutRequestEncoded = encodeAuthnRequest(logoutRequest);

        relayState = UUID.randomUUID().toString();
        String logoutURL = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?";
        logoutURL += SSOConstants.RELAY_STATE + "=" + relayState;
        logoutURL += "&" + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(logoutRequestEncoded, UTF_8.name());

        webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(USER, PWD));

        webClient.getOptions().setJavaScriptEnabled(false);
        idpPage = webClient.getPage(logoutURL);
        webClient.getOptions().setJavaScriptEnabled(true);

        Assertions.assertEquals("IDP SignOut Confirmation Response Page", idpPage.getTitleText());

        HtmlForm form = idpPage.getFormByName("signoutconfirmationresponseform");
        HtmlSubmitInput button = form.getInputByName("_eventId_cancel");
        HtmlPage signoutPage = button.click();

        // Check Response
        HtmlForm responseForm = signoutPage.getFormByName("samlsignoutresponseform");
        String logoutResponseURL = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/logout";
        Assertions.assertEquals(logoutResponseURL, responseForm.getActionAttribute());
        String responseValue = responseForm.getInputByName("SAMLResponse").getAttributeNS(null, "value");
        Assertions.assertNotNull(responseValue);
        String receivedRelayState = responseForm.getInputByName("RelayState").getAttributeNS(null, "value");
        Assertions.assertEquals(relayState, receivedRelayState);

        byte[] deflatedToken = Base64Utility.decode(responseValue);
        InputStream tokenStream = new ByteArrayInputStream(deflatedToken);
        Document responseDoc = StaxUtils.read(new InputStreamReader(tokenStream, UTF_8));

        LogoutResponse logoutResponse = (LogoutResponse)OpenSAMLUtil.fromDom(responseDoc.getDocumentElement());
        Assertions.assertNotNull(logoutResponse);
        Assertions.assertEquals(logoutResponseURL, logoutResponse.getDestination());
        String expectedIssuer = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml";
        Assertions.assertEquals(expectedIssuer, logoutResponse.getIssuer().getValue());
        String success = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        Assertions.assertEquals(success, logoutResponse.getStatus().getStatusCode().getValue());

        Assertions.assertNotNull(logoutResponse.getSignature());
        webClient.close();

        // 3. now we try to access the idp without authentication but with the existing cookies
        // to see if we are really logged out - we should still be logged in as we cancelled the Logout process
        webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
        idpPage = webClient.getPage(url);

        Assertions.assertEquals(200, idpPage.getWebResponse().getStatusCode());

        webClient.close();
    }

    private static String encodeAuthnRequest(XMLObject request) throws WSSecurityException {
        Document doc = DOMUtils.createDocument();
        doc.appendChild(doc.createElement("root"));
        String requestMessage = DOM2Writer.nodeToString(OpenSAMLUtil.toDom(request, doc));

        DeflateEncoderDecoder encoder = new DeflateEncoderDecoder();
        byte[] deflatedBytes = encoder.deflateToken(requestMessage.getBytes(UTF_8));

        return Base64Utility.encode(deflatedBytes);
    }

    private static void signAuthnRequest(SignableSAMLObject signableObject) throws Exception {
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

        signableObject.setSignature(signature);
        signableObject.releaseDOM();
        signableObject.releaseChildrenDOM(true);

    }

    private static org.opensaml.saml.saml2.core.Response parseSAMLResponse(HtmlPage idpPage,
                                                                    String relayState,
                                                                    String consumerURL,
                                                                    String authnRequestId
    ) throws Exception {
        Assertions.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        // Parse the form to get the token (SAMLResponse)
        DomNodeList<DomElement> results = idpPage.getElementsByTagName("input");

        String samlResponse = null;
        boolean foundRelayState = false;
        for (DomElement result : results) {
            if ("SAMLResponse".equals(result.getAttributeNS(null, "name"))) {
                samlResponse = result.getAttributeNS(null, "value");
            } else if ("RelayState".equals(result.getAttributeNS(null, "name"))) {
                foundRelayState = true;
                Assertions.assertEquals(result.getAttributeNS(null, "value"), relayState);
            }
        }

        Assertions.assertNotNull(samlResponse);
        Assertions.assertTrue(foundRelayState);

        // Check the "action"
        DomNodeList<DomElement> formResults = idpPage.getElementsByTagName("form");
        Assertions.assertFalse(formResults.isEmpty());

        DomElement formResult = formResults.get(0);
        String action = formResult.getAttributeNS(null, "action");
        Assertions.assertTrue(action.equals(consumerURL));

        // Decode + verify response
        byte[] deflatedToken = Base64Utility.decode(samlResponse);
        InputStream inputStream = new ByteArrayInputStream(deflatedToken);

        Document responseDoc = StaxUtils.read(new InputStreamReader(inputStream, UTF_8.name()));

        XMLObject responseObject = OpenSAMLUtil.fromDom(responseDoc.getDocumentElement());
        Assertions.assertTrue(responseObject instanceof org.opensaml.saml.saml2.core.Response);

        org.opensaml.saml.saml2.core.Response samlResponseObject =
            (org.opensaml.saml.saml2.core.Response)responseObject;
        Assertions.assertTrue(authnRequestId.equals(samlResponseObject.getInResponseTo()));

        return samlResponseObject;
    }

}
