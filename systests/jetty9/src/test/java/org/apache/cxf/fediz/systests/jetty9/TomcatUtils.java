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

package org.apache.cxf.fediz.systests.jetty9;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;

import org.junit.jupiter.api.Assertions;

public final class TomcatUtils {

    private static final String IDP_HTTPS_PORT = System.getProperty("idp.https.port");

    private static Tomcat idpServer;

    private TomcatUtils() {
    }

    public static void initIdpServer() throws Exception {
        Assertions.assertNotNull("Property 'idp.https.port' null", IDP_HTTPS_PORT);
        if (idpServer == null) {
            idpServer = new Tomcat();
            idpServer.setPort(0);
            final Path targetDir = Paths.get("target").toAbsolutePath();
            idpServer.setBaseDir(targetDir.toString());

            idpServer.getHost().setAppBase("tomcat/idp/webapps");
            idpServer.getHost().setAutoDeploy(true);
            idpServer.getHost().setDeployOnStartup(true);

            final Connector httpsConnector = new Connector();
            httpsConnector.setPort(Integer.parseInt(IDP_HTTPS_PORT));
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

            idpServer.getService().addConnector(httpsConnector);

            final Path stsWebapp = targetDir.resolve(idpServer.getHost().getAppBase()).resolve("fediz-idp-sts");
            idpServer.addWebapp("/fediz-idp-sts", stsWebapp.toString());

            final Path idpWebapp = targetDir.resolve(idpServer.getHost().getAppBase()).resolve("fediz-idp");
            idpServer.addWebapp("/fediz-idp", idpWebapp.toString());

            idpServer.start();
        }
    }

    public static String getIdpHttpsPort() {
        return IDP_HTTPS_PORT;
    }

    public static void stopIdpServer() throws Exception {
        if (idpServer != null && idpServer.getServer() != null
            && idpServer.getServer().getState() != LifecycleState.DESTROYED) {
            if (idpServer.getServer().getState() != LifecycleState.STOPPED) {
                idpServer.stop();
            }
            idpServer.destroy();
        }
    }

}
