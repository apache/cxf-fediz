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
package org.apache.cxf.fediz.service.idp.beans;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.SAMLSSOConstants;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.service.idp.IdpConstants;
import org.apache.cxf.fediz.service.idp.domain.Application;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

@Component
public class SigninParametersCacheAction {

    @Deprecated
    public static final String REALM_URL_MAP = "realmUrlMap";
    public static final String ACTIVE_APPLICATIONS = "realmConfigMap";

    private static final Logger LOG = LoggerFactory.getLogger(SigninParametersCacheAction.class);

    public void store(RequestContext context) {
        Map<String, Object> signinParams = new HashMap<>();
        String uuidKey = UUID.randomUUID().toString();
        
        Object value = WebUtils.getAttributeFromFlowScope(context, FederationConstants.PARAM_REPLY);
        if (value != null) {
            signinParams.put(FederationConstants.PARAM_REPLY, value);
        }
        value = WebUtils.getAttributeFromFlowScope(context, FederationConstants.PARAM_TREALM);
        if (value != null) {
            signinParams.put(FederationConstants.PARAM_TREALM, value);
        }
        value = WebUtils.getAttributeFromFlowScope(context, FederationConstants.PARAM_HOME_REALM);
        if (value != null) {
            signinParams.put(FederationConstants.PARAM_HOME_REALM, value);
        }
        value = WebUtils.getAttributeFromFlowScope(context, FederationConstants.PARAM_CONTEXT);
        if (value != null) {
            signinParams.put(FederationConstants.PARAM_CONTEXT, value);
        }
        WebUtils.putAttributeInExternalContext(context, uuidKey, signinParams);
        
        LOG.debug("SignIn parameters cached: {}", signinParams.toString());
        WebUtils.putAttributeInFlowScope(context, IdpConstants.TRUSTED_IDP_CONTEXT, uuidKey);
        LOG.info("SignIn parameters cached and context set to [" + uuidKey + "].");
    }
    
    public void restore(RequestContext context) {
        
        String uuidKey = (String)WebUtils.getAttributeFromFlowScope(context, FederationConstants.PARAM_CONTEXT);
        
        if (uuidKey == null) {
            uuidKey = (String)WebUtils.getAttributeFromFlowScope(context, SAMLSSOConstants.RELAY_STATE);
        }
        if (uuidKey == null) {
            uuidKey = (String)WebUtils.getAttributeFromFlowScope(context, OAuthConstants.STATE);
        }
        
        if (uuidKey != null) {
            @SuppressWarnings("unchecked")
            Map<String, Object> signinParams =
                (Map<String, Object>)WebUtils.getAttributeFromExternalContext(context, uuidKey);
            
            if (signinParams != null) {
                String value = (String)signinParams.get(FederationConstants.PARAM_REPLY);
                if (value != null) {
                    WebUtils.putAttributeInFlowScope(context, FederationConstants.PARAM_REPLY, value);
                }
                value = (String)signinParams.get(FederationConstants.PARAM_TREALM);
                if (value != null) {
                    WebUtils.putAttributeInFlowScope(context, FederationConstants.PARAM_TREALM, value);
                }
                value = (String)signinParams.get(FederationConstants.PARAM_HOME_REALM);
                if (value != null) {
                    WebUtils.putAttributeInFlowScope(context, FederationConstants.PARAM_HOME_REALM, value);
                }
                
                LOG.debug("SignIn parameters restored: {}", signinParams.toString());
                WebUtils.removeAttributeFromFlowScope(context, FederationConstants.PARAM_CONTEXT);
                LOG.info("SignIn parameters restored and " + FederationConstants.PARAM_CONTEXT + "[" 
                    + uuidKey + "] cleared.");
                
                value = (String)signinParams.get(FederationConstants.PARAM_CONTEXT);
                if (value != null) {
                    WebUtils.putAttributeInFlowScope(context, FederationConstants.PARAM_CONTEXT, value);
                }
            }  else {
                LOG.debug("Error in restoring security context");
            }
        } else {
            LOG.debug("Error in restoring security context");
        }
    }

    public void storeRPConfigInSession(RequestContext context) throws ProcessingException {

        String wtrealm = (String)WebUtils.getAttributeFromFlowScope(context, FederationConstants.PARAM_TREALM);
        Idp idpConfig = (Idp) WebUtils.getAttributeFromFlowScope(context, IdpConstants.IDP_CONFIG);
        if (wtrealm == null || idpConfig == null) {
            return;
        }       
        
        Application serviceConfig = idpConfig.findApplication(wtrealm);
        if (serviceConfig != null) {
            if (serviceConfig.getPassiveRequestorEndpoint() == null) {
                String url = guessPassiveRequestorURL(context, wtrealm);
                serviceConfig.setPassiveRequestorEndpoint(url);
            }
            
            @SuppressWarnings("unchecked")
            Map<String, Application> realmConfigMap =
                    (Map<String, Application>)WebUtils
                            .getAttributeFromExternalContext(context, ACTIVE_APPLICATIONS);

            if (realmConfigMap == null) {
                realmConfigMap = new HashMap<>();
                WebUtils.putAttributeInExternalContext(context, ACTIVE_APPLICATIONS, realmConfigMap);
            }

            if (realmConfigMap.get(wtrealm) == null) {
                realmConfigMap.put(wtrealm, serviceConfig);
            }
        }
    }

    protected String guessPassiveRequestorURL(RequestContext context, String wtrealm) throws ProcessingException {
        String url = (String)WebUtils.getAttributeFromFlowScope(context, FederationConstants.PARAM_REPLY);
        try {
            //basic check if the url is correctly formed
            new URL(url);
        } catch (Exception e) {
            url = null;
        }
        if (url == null) {
            url = wtrealm;
            try {
                //basic check if the url is correctly formed
                new URL(url);
            } catch (Exception e) {
                throw new ProcessingException(e.getMessage(), e, ProcessingException.TYPE.INVALID_REQUEST);
            }
        }
        return url;
    }
}
