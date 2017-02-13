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

package org.apache.cxf.fediz.jetty9;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.security.auth.Subject;
import javax.servlet.ServletRequest;

import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.processor.FedizProcessor;
import org.apache.cxf.fediz.core.processor.FedizProcessorFactory;
import org.apache.cxf.fediz.core.processor.FedizRequest;
import org.apache.cxf.fediz.core.processor.FedizResponse;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.util.component.AbstractLifeCycle;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;

public class FederationLoginService extends AbstractLifeCycle implements LoginService {
    private static final Logger LOG = Log.getLogger(FederationLoginService.class);

    protected IdentityService identityService = new FederationIdentityService();
    protected String name;


    public FederationLoginService() {
    }

    public FederationLoginService(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

    public void setName(String name) {
        if (isRunning()) {
            throw new IllegalStateException("Running");
        }

        this.name = name;
    }

    @Override
    protected void doStart() throws Exception {
        LOG.debug("doStart");
        super.doStart();
    }

    /**
     * username will be null since the credentials will contain all the relevant info
     */
    public UserIdentity login(String username, Object credentials, FedizContext config) {

        try {
            FedizResponse wfRes = null;
            FedizRequest wfReq = (FedizRequest)credentials;

            if (LOG.isDebugEnabled()) {
                LOG.debug("Process SignIn request");
                LOG.debug("token=\n" + wfReq.getResponseToken());
            }

            FedizProcessor wfProc =
                FedizProcessorFactory.newFedizProcessor(config.getProtocol());
            try {
                wfRes = wfProc.processRequest(wfReq, config);
            } catch (ProcessingException ex) {
                LOG.warn("Federation processing failed: " + ex.getMessage());
                return null;
            }


            // Validate the AudienceRestriction in Security Token (e.g. SAML)
            // against the configured list of audienceURIs
            if (wfRes.getAudience() != null) {
                List<String> audienceURIs = config.getAudienceUris();
                boolean validAudience = false;
                for (String a : audienceURIs) {
                    if (wfRes.getAudience().startsWith(a)) {
                        validAudience = true;
                        break;
                    }
                }

                if (!validAudience) {
                    LOG.warn("Token AudienceRestriction [" + wfRes.getAudience()
                             + "] doesn't match with specified list of URIs.");
                    return null;
                }
            }

            // Add "Authenticated" role
            List<String> roles = wfRes.getRoles();
            if (roles == null || roles.isEmpty()) {
                roles = Collections.singletonList("Authenticated");
            } else if (config.isAddAuthenticatedRole()) {
                roles = new ArrayList<>(roles);
                roles.add("Authenticated");
            }

            FederationUserPrincipal user = new FederationUserPrincipal(wfRes.getUsername(), wfRes);

            Subject subject = new Subject();
            subject.getPrincipals().add(user);

            String[] aRoles = new String[roles.size()];
            roles.toArray(aRoles);

            return identityService.newUserIdentity(subject, user, aRoles);

        } catch (Exception ex) {
            LOG.warn(ex);
        }

        return null;
    }

    public boolean validate(UserIdentity user) {
        try {
            FederationUserIdentity fui = (FederationUserIdentity)user;
            return fui.getExpiryDate().after(new Date());
        } catch (ClassCastException ex) {
            LOG.warn("UserIdentity must be instance of FederationUserIdentity");
            throw new IllegalStateException("UserIdentity must be instance of FederationUserIdentity");
        }
    }

    @Override
    public IdentityService getIdentityService() {
        return identityService;
    }

    @Override
    public void setIdentityService(IdentityService service) {
        identityService = service;
    }

    public void logout(UserIdentity user) {

    }

    @Override
    public UserIdentity login(String username, Object credentials, ServletRequest arg2) {
        return null;
    }

}
