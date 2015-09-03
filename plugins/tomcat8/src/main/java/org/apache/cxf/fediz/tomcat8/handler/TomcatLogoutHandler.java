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

package org.apache.cxf.fediz.tomcat8.handler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Session;
import org.apache.catalina.connector.Request;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.handler.LogoutHandler;
import org.apache.cxf.fediz.tomcat8.FederationAuthenticator;

public class TomcatLogoutHandler extends LogoutHandler {
    private final Request request;

    public TomcatLogoutHandler(FedizContext fedConfig, String servletContextPath, Request request) {
        super(fedConfig, servletContextPath);
        this.request = request;
    }

    @Override
    protected boolean signoutCleanup(HttpServletRequest req, HttpServletResponse resp) {
        // Cleanup session internal
        Session session = request.getSessionInternal();
        session.removeNote(FederationAuthenticator.FEDERATION_NOTE);
        session.setPrincipal(null);
        super.signoutCleanup(req, resp);
        request.clearCookies();
        return true;
    }

    @Override
    protected boolean signout(HttpServletRequest req, HttpServletResponse resp) {
        // Direct Logout
        Session session = request.getSessionInternal();
        session.removeNote(FederationAuthenticator.FEDERATION_NOTE);
        session.setPrincipal(null);
        return super.signout(req, resp);
    }
}
