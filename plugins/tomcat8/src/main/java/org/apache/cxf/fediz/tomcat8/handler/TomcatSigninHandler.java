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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.connector.Request;
import org.apache.cxf.fediz.core.FedizPrincipal;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.handler.SigninHandler;
import org.apache.cxf.fediz.core.processor.FedizResponse;
import org.apache.cxf.fediz.tomcat8.FederationAuthenticator;
import org.apache.cxf.fediz.tomcat8.FederationPrincipalImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TomcatSigninHandler extends SigninHandler<FedizPrincipal> {

    private static final Logger LOG = LoggerFactory.getLogger(TomcatSigninHandler.class);
    private Object landingPage;

    public TomcatSigninHandler(FedizContext fedizContext) {
        super(fedizContext);
    }

    @Override
    protected FedizPrincipal createPrincipal(HttpServletRequest request, HttpServletResponse response,
        FedizResponse wfRes) {

        // Add "Authenticated" role
        List<String> roles = wfRes.getRoles();
        if (roles == null || roles.size() == 0) {
            roles = Collections.singletonList("Authenticated");
        } else if (getFedizContext().isAddAuthenticatedRole()) {
            roles = new ArrayList<>(roles);
            roles.add("Authenticated");
        }

        // proceed creating the JAAS Subject
        FedizPrincipal principal = new FederationPrincipalImpl(wfRes.getUsername(), roles,
                                                               wfRes.getClaims(), wfRes.getToken());

        Session session = ((Request)request).getSessionInternal();

        // Save the authenticated Principal in our session
        session.setNote(Constants.FORM_PRINCIPAL_NOTE, principal);

        // Save Federation response in our session
        session.setNote(FederationAuthenticator.FEDERATION_NOTE, wfRes);

        // Save Federation response in public session
        request.getSession(true).setAttribute(FederationAuthenticator.SECURITY_TOKEN, wfRes.getToken());

        LOG.debug("UserPrincipal was created successfully for {}", principal);
        return principal;
    }

    public Object getLandingPage() {
        return landingPage;
    }

    public void setLandingPage(Object landingPage) {
        this.landingPage = landingPage;
    }

}
