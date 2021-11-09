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

package org.apache.cxf.fediz.systests.ldap;


import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import javax.servlet.ServletException;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.systests.common.HTTPTestUtils;
import org.apache.cxf.fediz.tomcat.FederationAuthenticator;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreateIndex;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.apache.wss4j.dom.engine.WSSConfig;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * A test that configures the STS to authenticate user (and retrieve claims) from an LDAP backend.
 */

@RunWith(FrameworkRunner.class)

//Define the DirectoryService
@CreateDS(name = "LDAPTest-class",
        enableAccessControl = false,
        allowAnonAccess = false,
        enableChangeLog = true,
        partitions = {
            @CreatePartition(
                name = "fediz",
                suffix = "dc=fediz,dc=org",
                indexes = {
                    @CreateIndex(attribute = "objectClass"),
                    @CreateIndex(attribute = "dc"),
                    @CreateIndex(attribute = "ou")
                }
            )
        }
  )

@CreateLdapServer(
    transports = {
        @CreateTransport(protocol = "LDAP", address = "localhost")
        // @CreateTransport(protocol = "LDAP", address = "localhost", port = 12345)
    }
)

//Inject an file containing entries
@ApplyLdifFiles("ldap.ldif")

public class LDAPTest extends AbstractLdapTestUnit {

    static String idpHttpsPort;
    static String rpHttpsPort;

    private static Tomcat idpServer;
    private static Tomcat rpServer;
    private static boolean portUpdated;

    @Before
    public void init() throws Exception {
        idpHttpsPort = System.getProperty("idp.https.port");
        Assert.assertNotNull("Property 'idp.https.port' null", idpHttpsPort);
        rpHttpsPort = System.getProperty("rp.https.port");
        Assert.assertNotNull("Property 'rp.https.port' null", rpHttpsPort);

        WSSConfig.init();

        updatePort();

        idpServer = startServer(true, idpHttpsPort);
        rpServer = startServer(false, rpHttpsPort);
    }

    private void updatePort() throws Exception {
        if (!portUpdated) {
            String basedir = System.getProperty("basedir");
            if (basedir == null) {
                basedir = new File(".").getCanonicalPath();
            }

            // Read in ldap.xml and substitute in the correct port
            File f = new File(basedir + "/src/test/resources/sts/ldap.xml");

            String content = new String(Files.readAllBytes(f.toPath()), "UTF-8");
            content = content.replaceAll("portno", Integer.toString(getLdapServer().getPort()));

            File f2 = new File(basedir + "/target/tomcat/idp/webapps/fediz-idp-sts/WEB-INF/endpoints/ldap.xml");
            Files.write(f2.toPath(), content.getBytes());

            // Read in ldap.jaas and substitute in the correct port
            f = new File(basedir + "/src/test/resources/ldap.jaas");
            content = new String(Files.readAllBytes(f.toPath()), "UTF-8");
            content = content.replaceAll("portno", Integer.toString(getLdapServer().getPort()));

            f2 = new File(basedir + "/target/test-classes/ldap.jaas");
            Files.write(f2.toPath(), content.getBytes());

            portUpdated = true;
        }

        System.setProperty("java.security.auth.login.config", "target/test-classes/ldap.jaas");
    }

    private static Tomcat startServer(boolean idp, String port)
        throws ServletException, LifecycleException, IOException {
        Tomcat server = new Tomcat();
        server.setPort(0);
        String currentDir = new File(".").getCanonicalPath();
        String baseDir = currentDir + File.separator + "target";
        server.setBaseDir(baseDir);

        if (idp) {
            server.getHost().setAppBase("tomcat/idp/webapps");
        } else {
            server.getHost().setAppBase("tomcat/rp/webapps");
        }
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

        if (idp) {
            File stsWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp-sts");
            server.addWebapp("/fediz-idp-sts", stsWebapp.getAbsolutePath());

            File idpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp");
            server.addWebapp("/fediz-idp", idpWebapp.getAbsolutePath());
        } else {
            File rpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "simpleWebapp");
            Context cxt = server.addWebapp("/fedizhelloworld", rpWebapp.getAbsolutePath());

            FederationAuthenticator fa = new FederationAuthenticator();
            fa.setConfigFile(currentDir + File.separator + "target" + File.separator
                             + "test-classes" + File.separator + "fediz_config.xml");
            cxt.getPipeline().addValve(fa);
        }

        server.start();

        return server;
    }

    @After
    public void cleanup() {
        shutdownServer(idpServer);
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

    /*
    @Test
    public void testStart() throws Exception {
        System.out.println("Sleeping...");
        Thread.sleep(5 * 60 * 1000);
    }
    */

    @Test
    public void testLDAP() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/fedservlet";
        String user = "alice";
        String password = "ecila";

        final String bodyTextContent =
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort(), "signinresponseform");

        Assert.assertTrue("Principal not " + user,
                          bodyTextContent.contains("userPrincipal=" + user));
        Assert.assertTrue("User " + user + " does not have role Admin",
                          bodyTextContent.contains("role:Admin=false"));
        Assert.assertTrue("User " + user + " does not have role Manager",
                          bodyTextContent.contains("role:Manager=false"));
        Assert.assertTrue("User " + user + " must have role User",
                          bodyTextContent.contains("role:User=true"));

        String claim = ClaimTypes.FIRSTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Alice'",
                          bodyTextContent.contains(claim + "=Alice"));
        claim = ClaimTypes.LASTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Smith'",
                          bodyTextContent.contains(claim + "=Smith"));
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'alice@realma.org'",
                          bodyTextContent.contains(claim + "=alice@realma.org"));

    }


}
