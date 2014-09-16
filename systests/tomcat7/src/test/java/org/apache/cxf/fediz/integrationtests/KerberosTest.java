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

package org.apache.cxf.fediz.integrationtests;


import java.io.File;

/*
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.FormField;
import net.htmlparser.jericho.FormFields;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
*/
import org.apache.catalina.Context;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.cxf.fediz.tomcat.FederationAuthenticator;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;

/**
 * A test that sends a Kerberos ticket to the IdP for authentication. The IdP must be configured
 * to validate the Kerberos ticket, and in turn get a delegation token to authenticate to the
 * STS + retrieve claims etc.
 */
@org.junit.Ignore
public class KerberosTest {

    static String idpHttpsPort;
    static String rpHttpsPort;
    
    private static Tomcat idpServer;
    private static Tomcat rpServer;
    
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
        initRp();
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
    
    private static void initRp() {
        try {
            rpServer = new Tomcat();
            rpServer.setPort(0);
            String currentDir = new File(".").getCanonicalPath();
            rpServer.setBaseDir(currentDir + File.separator + "target");
            
            rpServer.getHost().setAppBase("tomcat/rp/webapps");
            rpServer.getHost().setAutoDeploy(true);
            rpServer.getHost().setDeployOnStartup(true);
            
            Connector httpsConnector = new Connector();
            httpsConnector.setPort(Integer.parseInt(rpHttpsPort));
            httpsConnector.setSecure(true);
            httpsConnector.setScheme("https");
            //httpsConnector.setAttribute("keyAlias", keyAlias);
            httpsConnector.setAttribute("keystorePass", "tompass");
            httpsConnector.setAttribute("keystoreFile", "test-classes/server.jks");
            httpsConnector.setAttribute("truststorePass", "tompass");
            httpsConnector.setAttribute("truststoreFile", "test-classes/server.jks");
            // httpsConnector.setAttribute("clientAuth", "false");
            httpsConnector.setAttribute("clientAuth", "want");
            httpsConnector.setAttribute("sslProtocol", "TLS");
            httpsConnector.setAttribute("SSLEnabled", true);

            rpServer.getService().addConnector(httpsConnector);
            
            //Context ctx =
            Context cxt = rpServer.addWebapp("/fedizhelloworld", "simpleWebapp");
            FederationAuthenticator fa = new FederationAuthenticator();
            fa.setConfigFile(currentDir + File.separator + "target" + File.separator
                             + "test-classes" + File.separator + "fediz_config.xml");
            cxt.getPipeline().addValve(fa);
            
            
            rpServer.start();
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

        try {
            if (rpServer.getServer() != null
                && rpServer.getServer().getState() != LifecycleState.DESTROYED) {
                if (rpServer.getServer().getState() != LifecycleState.STOPPED) {
                    rpServer.stop();
                }
                rpServer.destroy();
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
    /*
    @org.junit.Test
    public void testKerberos() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        // Get a Kerberos Ticket +  Base64 encode it
        String ticket = getEncodedKerberosTicket(false);
        
        String response = sendHttpGet(url, ticket, 200, 200, Integer.parseInt(getIdpHttpsPort()));

        String user = "alice";
        Assert.assertTrue("Principal not " + user, response.indexOf("userPrincipal=" + user) > 0);
        Assert.assertTrue("User " + user + " does not have role Admin", response.indexOf("role:Admin=false") > 0);
        Assert.assertTrue("User " + user + " does not have role Manager", response.indexOf("role:Manager=false") > 0);
        Assert.assertTrue("User " + user + " must have role User", response.indexOf("role:User=true") > 0);

        String claim = ClaimTypes.FIRSTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Alice'",
                          response.indexOf(claim + "=Alice") > 0);
        claim = ClaimTypes.LASTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Smith'",
                          response.indexOf(claim + "=Smith") > 0);
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'alice@realma.org'",
                          response.indexOf(claim + "=alice@realma.org") > 0);
    
    }
    
    @org.junit.Test
    public void testSpnego() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        // Get a Kerberos Ticket +  Base64 encode it
        String ticket = getEncodedKerberosTicket(true);
        
        String response = sendHttpGet(url, ticket, 200, 200, Integer.parseInt(getIdpHttpsPort()));

        String user = "alice";
        Assert.assertTrue("Principal not " + user, response.indexOf("userPrincipal=" + user) > 0);
        Assert.assertTrue("User " + user + " does not have role Admin", response.indexOf("role:Admin=false") > 0);
        Assert.assertTrue("User " + user + " does not have role Manager", response.indexOf("role:Manager=false") > 0);
        Assert.assertTrue("User " + user + " must have role User", response.indexOf("role:User=true") > 0);

        String claim = ClaimTypes.FIRSTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Alice'",
                          response.indexOf(claim + "=Alice") > 0);
        claim = ClaimTypes.LASTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Smith'",
                          response.indexOf(claim + "=Smith") > 0);
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'alice@realma.org'",
                          response.indexOf(claim + "=alice@realma.org") > 0);
    
    }
    
    private String getEncodedKerberosTicket(boolean spnego) throws Exception {
        
        System.setProperty("java.security.auth.login.config", "src/test/resources/kerberos.jaas");
        System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
        
        Oid kerberos5Oid = null;
        if (spnego) {
            kerberos5Oid = new Oid("1.3.6.1.5.5.2");
        } else {
            kerberos5Oid = new Oid("1.2.840.113554.1.2.2");
        }
        
        GSSManager manager = GSSManager.getInstance();
        GSSName serverName = manager.createName("bob@service.ws.apache.org", 
                                                GSSName.NT_HOSTBASED_SERVICE);

        GSSContext context = manager
                .createContext(serverName.canonicalize(kerberos5Oid), kerberos5Oid, 
                               null, GSSContext.DEFAULT_LIFETIME);
        
        context.requestCredDeleg(true);
        
        final byte[] token = new byte[0];

        String contextName = "alice";
        LoginContext lc = new LoginContext(contextName);
        lc.login();
        
        byte[] ticket = (byte[])Subject.doAs(lc.getSubject(), new CreateServiceTicketAction(context, token));
        return Base64.encode(ticket);
    }
    
    private final class CreateServiceTicketAction implements PrivilegedExceptionAction<byte[]> {
        private final GSSContext context;
        private final byte[] token;

        private CreateServiceTicketAction(GSSContext context, byte[] token) {
            this.context = context;
            this.token = token;
        }

        public byte[] run() throws GSSException {
            return context.initSecContext(token, 0, token.length);
        }
    }
    
    public static String sendHttpGet(String url, String ticket,
                                     int returnCodeIDP, int returnCodeRP, int idpPort)
        throws Exception {
        
        CloseableHttpClient httpClient = null;
        try {
            KeyStore trustStore  = KeyStore.getInstance(KeyStore.getDefaultType());
            FileInputStream instream = new FileInputStream(new File("./target/test-classes/client.jks"));
            try {
                trustStore.load(instream, "clientpass".toCharArray());
            } finally {
                try {
                    instream.close();
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }

            SSLContextBuilder sslContextBuilder = new SSLContextBuilder();
            sslContextBuilder.loadTrustMaterial(trustStore, new TrustSelfSignedStrategy());
            sslContextBuilder.loadKeyMaterial(trustStore, "clientpass".toCharArray());
            
            SSLContext sslContext = sslContextBuilder.build();
            SSLConnectionSocketFactory sslSocketFactory = 
                new SSLConnectionSocketFactory(sslContext);
            
            HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
            httpClientBuilder.setSSLSocketFactory(sslSocketFactory);
            httpClientBuilder.setRedirectStrategy(new LaxRedirectStrategy());
            
            httpClient = httpClientBuilder.build();
            
            HttpGet httpget = new HttpGet(url);
            httpget.addHeader("Authorization", "Negotiate " + ticket);

            HttpResponse response = httpClient.execute(httpget);
            HttpEntity entity = response.getEntity();

            System.out.println(response.getStatusLine());
            if (entity != null) {
                System.out.println("Response content length: " + entity.getContentLength());
            }
            Assert.assertTrue("IDP HTTP Response code: " + response.getStatusLine().getStatusCode()
                              + " [Expected: " + returnCodeIDP + "]",
                              returnCodeIDP == response.getStatusLine().getStatusCode());

            if (response.getStatusLine().getStatusCode() != 200) {
                return null;
            }

            //            Redirect to a POST is not supported without user interaction
            //            http://www.ietf.org/rfc/rfc2616.txt
            //            If the 301 status code is received in response to a request other
            //            than GET or HEAD, the user agent MUST NOT automatically redirect the
            //            request unless it can be confirmed by the user, since this might
            //            change the conditions under which the request was issued.
            
            Source source = new Source(EntityUtils.toString(entity));
            List <NameValuePair> nvps = new ArrayList <NameValuePair>();
            FormFields formFields = source.getFormFields();
            
            List<Element> forms = source.getAllElements(HTMLElementName.FORM);
            Assert.assertEquals("Only one form expected but got " + forms.size(), 1, forms.size());
            String postUrl = forms.get(0).getAttributeValue("action");
            
            Assert.assertNotNull("Form field 'wa' not found", formFields.get("wa"));
            Assert.assertNotNull("Form field 'wresult' not found", formFields.get("wresult"));
            
            for (FormField formField : formFields) {
                if (formField.getUserValueCount() != 0) {
                    nvps.add(new BasicNameValuePair(formField.getName(),
                             formField.getValues().get(0)));
                }
            } 
            HttpPost httppost = new HttpPost(postUrl);
            httppost.setEntity(new UrlEncodedFormEntity(nvps, Consts.UTF_8));

            response = httpClient.execute(httppost);

            entity = response.getEntity();
            System.out.println(response.getStatusLine());
            Assert.assertTrue("RP HTTP Response code: " + response.getStatusLine().getStatusCode()
                              + " [Expected: " + returnCodeRP + "]",
                              returnCodeRP == response.getStatusLine().getStatusCode());

            if (entity != null) {
                System.out.println("Response content length: " + entity.getContentLength());
            }

            return EntityUtils.toString(entity);
        } finally {
            // When HttpClient instance is no longer needed,
            // shut down the connection manager to ensure
            // immediate deallocation of all system resources
            if (httpClient != null) {
                httpClient.close();
            }
        }
    }
    */
}
