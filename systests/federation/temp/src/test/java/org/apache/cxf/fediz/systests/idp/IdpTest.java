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
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.UUID;

import javax.servlet.ServletException;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.cxf.fediz.tomcat7.FederationAuthenticator;
import org.apache.cxf.rs.security.saml.DeflateEncoderDecoder;
import org.apache.cxf.rs.security.saml.sso.DefaultAuthnRequestBuilder;
import org.apache.cxf.rs.security.saml.sso.SSOConstants;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.dom.engine.WSSConfig;
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
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

/**
 * Some tests invoking directly on the IdP for SAML SSO
 */
public class IdpTest {

    static String idpHttpsPort;
    static String rpHttpsPort;
    static String idpRealmbHttpsPort;

    private static Tomcat idpServer;
    private static Tomcat idpRealmbServer;
    private static Tomcat rpServer;

    @BeforeClass
    public static void init() throws Exception {
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
        idpRealmbHttpsPort = System.getProperty("idp.realmb.https.port");
        Assert.assertNotNull("Property 'idp.realmb.https.port' null", idpRealmbHttpsPort);
        rpHttpsPort = System.getProperty("rp.https.port");
        Assert.assertNotNull("Property 'rp.https.port' null", rpHttpsPort);

        idpServer = startServer(true, false, idpHttpsPort);
        idpRealmbServer = startServer(false, true, idpRealmbHttpsPort);
        // rpServer = startServer(false, false, rpHttpsPort);

        WSSConfig.init();
    }

    private static Tomcat startServer(boolean idp, boolean realmb, String port) 
        throws ServletException, LifecycleException, IOException {
        Tomcat server = new Tomcat();
        server.setPort(0);
        String currentDir = new File(".").getCanonicalPath();
        String baseDir = currentDir + File.separator + "target";
        server.setBaseDir(baseDir);

        if (idp) {
            server.getHost().setAppBase("tomcat/idp/webapps");
        } else if (realmb) {
            server.getHost().setAppBase("tomcat/idprealmb/webapps");
        } else {
            server.getHost().setAppBase("tomcat/rp/webapps");
        }
        server.getHost().setAutoDeploy(true);
        server.getHost().setDeployOnStartup(true);

        Connector httpsConnector = new Connector();
        httpsConnector.setPort(Integer.parseInt(port));
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

        server.getService().addConnector(httpsConnector);

        if (idp) {
            File stsWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp-sts");
            server.addWebapp("/fediz-idp-sts", stsWebapp.getAbsolutePath());
    
            File idpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp");
            server.addWebapp("/fediz-idp", idpWebapp.getAbsolutePath());
        } else if (realmb) {
            File stsWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp-sts-realmb");
            server.addWebapp("/fediz-idp-sts-realmb", stsWebapp.getAbsolutePath());
    
            File idpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp-realmb");
            server.addWebapp("/fediz-idp-realmb", idpWebapp.getAbsolutePath());
        } else {
            File rpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "simpleWebapp");
            Context cxt = server.addWebapp("/fedizhelloworld", rpWebapp.getAbsolutePath());
            
            FederationAuthenticator fa = new FederationAuthenticator();
            fa.setConfigFile(currentDir + File.separator + "target" + File.separator
                             + "test-classes" + File.separator + "fediz_config_wsfed.xml");
            cxt.getPipeline().addValve(fa);
        }

        server.start();

        return server;
    }

    @AfterClass
    public static void cleanup() {
        shutdownServer(idpServer);
        shutdownServer(idpRealmbServer);
        shutdownServer(rpServer);
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

    public String getIdpHttpsPort() {
        return idpHttpsPort;
    }

    public String getRpHttpsPort() {
        return rpHttpsPort;
    }

    public String getServletContextName() {
        return "fedizhelloworld";
    }
    
    //
    // Successful tests
    //
    
    @org.junit.Test
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

        String urlEncodedRequest = URLEncoder.encode(authnRequestEncoded, "UTF-8");

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml?";
        url += SSOConstants.RELAY_STATE + "=" + relayState;
        url += "&" + SSOConstants.SAML_REQUEST + "=" + urlEncodedRequest;
        
        System.out.println("URL: " + url);
        
        Thread.sleep(60 * 1000);

    }
    /*
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
        
        org.opensaml.saml.saml2.core.Response samlResponse = 
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Assert.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());
        
        // Check claims
        String parsedResponse = DOM2Writer.nodeToString(samlResponse.getDOM().getOwnerDocument());
        String claim = ClaimTypes.FIRSTNAME.toString();
        Assert.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.LASTNAME.toString();
        Assert.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assert.assertTrue(parsedResponse.contains(claim));

        webClient.close();
    }
    
    @org.junit.Test
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
        String authnRequestEncoded = Base64Utility.encode(requestMessage.getBytes("UTF-8"));

        String relayState = UUID.randomUUID().toString();
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/saml/up";

        String user = "alice";
        String password = "ecila";

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);
        
        WebRequest request = new WebRequest(new URL(url), HttpMethod.POST);

        request.setRequestParameters(new ArrayList<NameValuePair>());
        request.getRequestParameters().add(new NameValuePair(SSOConstants.RELAY_STATE, relayState));
        request.getRequestParameters().add(new NameValuePair(SSOConstants.SAML_REQUEST, authnRequestEncoded));
        
        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(request);
        
        webClient.getOptions().setJavaScriptEnabled(true);
        Assert.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());
        
        org.opensaml.saml.saml2.core.Response samlResponse = 
            parseSAMLResponse(idpPage, relayState, consumerURL, authnRequest.getID());
        String expected = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Assert.assertEquals(expected, samlResponse.getStatus().getStatusCode().getValue());
        
        // Check claims
        String parsedResponse = DOM2Writer.nodeToString(samlResponse.getDOM().getOwnerDocument());
        String claim = ClaimTypes.FIRSTNAME.toString();
        Assert.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.LASTNAME.toString();
        Assert.assertTrue(parsedResponse.contains(claim));
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assert.assertTrue(parsedResponse.contains(claim));

        webClient.close();
    }
    */

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
    
    private org.opensaml.saml.saml2.core.Response parseSAMLResponse(HtmlPage idpPage, 
                                                                    String relayState, 
                                                                    String consumerURL,
                                                                    String authnRequestId
    ) throws Exception {
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
        Assert.assertTrue(authnRequestId.equals(samlResponseObject.getInResponseTo()));
        
        return samlResponseObject;
    }
}
