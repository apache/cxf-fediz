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

package org.apache.cxf.fediz.systests.federation.unknown;


import java.io.File;
import java.io.IOException;
import java.net.URLEncoder;

import javax.servlet.ServletException;

import com.gargoylesoftware.htmlunit.CookieManager;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.tomcat.FederationAuthenticator;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;

/**
 * This is a test for federation using a WS-Federation enabled web application. The web application is configured
 * to use a different realm to that of the IdP. The IdP then redirects to a third party IdP for authentication.
 * The subject of the trusted third party IdP is not known to the local STS of "realm A" however. Normally this
 * would result in failure, however the STS is configured to allow unknown principals for the realm of this
 * specific TTP IdP.
 */
public class WSFedTest {

    private enum ServerType {
        IDP, REALMB, RP
    }

    static String idpHttpsPort;
    static String idpRealmbHttpsPort;
    static String rpHttpsPort;

    private static Tomcat idpServer;
    private static Tomcat idpRealmbServer;
    private static Tomcat rpServer;

    @BeforeClass
    public static void init() throws Exception {
        idpHttpsPort = System.getProperty("idp.https.port");
        Assert.assertNotNull("Property 'idp.https.port' null", idpHttpsPort);
        idpRealmbHttpsPort = System.getProperty("idp.realmb.https.port");
        Assert.assertNotNull("Property 'idp.realmb.https.port' null", idpRealmbHttpsPort);
        rpHttpsPort = System.getProperty("rp.https.port");
        Assert.assertNotNull("Property 'rp.https.port' null", rpHttpsPort);

        idpServer = startServer(ServerType.IDP, idpHttpsPort);
        idpRealmbServer = startServer(ServerType.REALMB, idpRealmbHttpsPort);
        rpServer = startServer(ServerType.RP, rpHttpsPort);
    }

    private static Tomcat startServer(ServerType serverType, String port)
        throws ServletException, LifecycleException, IOException {
        Tomcat server = new Tomcat();
        server.setPort(0);
        String currentDir = new File(".").getCanonicalPath();
        String baseDir = currentDir + File.separator + "target";
        server.setBaseDir(baseDir);

        if (serverType == ServerType.IDP) {
            server.getHost().setAppBase("tomcat/idp/webapps");
        } else if (serverType == ServerType.REALMB) {
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
        httpsConnector.setAttribute("keyAlias", "mytomidpkey");
        httpsConnector.setAttribute("keystorePass", "tompass");
        httpsConnector.setAttribute("keystoreFile", "test-classes/server.jks");
        httpsConnector.setAttribute("truststorePass", "tompass");
        httpsConnector.setAttribute("truststoreFile", "test-classes/server.jks");
        httpsConnector.setAttribute("clientAuth", "want");
        // httpsConnector.setAttribute("clientAuth", "false");
        httpsConnector.setAttribute("sslProtocol", "TLS");
        httpsConnector.setAttribute("SSLEnabled", true);

        server.getService().addConnector(httpsConnector);

        if (serverType == ServerType.IDP) {
            File stsWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp-sts");
            server.addWebapp("/fediz-idp-sts", stsWebapp.getAbsolutePath());

            File idpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp");
            server.addWebapp("/fediz-idp", idpWebapp.getAbsolutePath());
        } else if (serverType == ServerType.REALMB) {
            File stsWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp-sts-realmb");
            server.addWebapp("/fediz-idp-sts-realmb", stsWebapp.getAbsolutePath());

            File idpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp-realmb");
            server.addWebapp("/fediz-idp-realmb", idpWebapp.getAbsolutePath());
        } else {
            File rpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "simpleWebapp");
            Context cxt = server.addWebapp("/wsfed", rpWebapp.getAbsolutePath());

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

    public String getIdpRealmbHttpsPort() {
        return idpRealmbHttpsPort;
    }

    public String getRpHttpsPort() {
        return rpHttpsPort;
    }

    public String getServletContextName() {
        return "fedizhelloworld";
    }

    @org.junit.Test
    public void testWSFederationUnknownSubject() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/wsfed/secure/fedservlet";
        // System.out.println(url);
        // Thread.sleep(60 * 2 * 1000);
        String user = "ALICE";  // realm b credentials
        String password = "ECILA";

        final String bodyTextContent =
            login(url, user, password, getIdpRealmbHttpsPort(), idpHttpsPort);

        // Test for "realm b" principal here
        Assert.assertTrue("Principal not ALICE",
                          bodyTextContent.contains("userPrincipal=ALICE"));

        String claim = ClaimTypes.EMAILADDRESS.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'alice@realmb.org'",
                          bodyTextContent.contains(claim + "=alice@realmb.org"));
    }

    private static String login(String url, String user, String password,
                                           String idpPort, String rpIdpPort) throws IOException {
        //
        // Access the RP + get redirected to the IdP for "realm a". Then get redirected to the IdP for
        // "realm b".
        //
        final WebClient webClient = new WebClient();
        CookieManager cookieManager = new CookieManager();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(idpPort)),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assert.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        // For some reason, redirecting back to the IdP for "realm a" is not working with htmlunit. So extract
        // the parameters manually from the form, and access the IdP for "realm a" with them
        DomNodeList<DomElement> results = idpPage.getElementsByTagName("input");

        String wresult = null;
        String wa = "wsignin1.0";
        String wctx = null;
        String wtrealm = null;
        for (DomElement result : results) {
            if ("wresult".equals(result.getAttributeNS(null, "name"))) {
                wresult = result.getAttributeNS(null, "value");
            } else if ("wctx".equals(result.getAttributeNS(null, "name"))) {
                wctx = result.getAttributeNS(null, "value");
            } else if ("wtrealm".equals(result.getAttributeNS(null, "name"))) {
                wtrealm = result.getAttributeNS(null, "value");
            }
        }
        Assert.assertTrue(wctx != null && wresult != null && wtrealm != null);
        webClient.close();

        // Invoke on the IdP for "realm a"
        final WebClient webClient2 = new WebClient();
        webClient2.setCookieManager(cookieManager);
        webClient2.getOptions().setUseInsecureSSL(true);

        String url2 = "https://localhost:" + rpIdpPort + "/fediz-idp/federation?";
        url2 += "wctx=" + wctx + "&";
        url2 += "wa=" + wa + "&";
        url2 += "wtrealm=" + URLEncoder.encode(wtrealm, "UTF8") + "&";
        url2 += "wresult=" + URLEncoder.encode(wresult, "UTF8");

        webClient2.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage2 = webClient2.getPage(url2);
        webClient2.getOptions().setJavaScriptEnabled(true);
        Assert.assertEquals("IDP SignIn Response Form", idpPage2.getTitleText());

        // Now redirect back to the RP
        final HtmlForm form2 = idpPage2.getFormByName("signinresponseform");

        final HtmlSubmitInput button2 = form2.getInputByName("_eventId_submit");

        final HtmlPage rpPage = button2.click();
        Assert.assertEquals("WS Federation Systests Examples", rpPage.getTitleText());

        webClient2.close();
        return rpPage.getBody().getTextContent();
    }


}
