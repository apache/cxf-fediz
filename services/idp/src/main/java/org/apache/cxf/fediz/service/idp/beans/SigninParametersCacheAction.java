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

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.RequestContext;

public class SigninParametersCacheAction {

    private static final Logger LOG = LoggerFactory.getLogger(SigninParametersCacheAction.class);

    public void store(RequestContext context) {
        Map<String, Object> signinParams = new HashMap<String, Object>();
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
        WebUtils.putAttributeInExternalContext(context, uuidKey, signinParams);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("SignIn parameters cached: " + signinParams.toString() + ".");
        }
        WebUtils.putAttributeInFlowScope(context, FederationConstants.PARAM_CONTEXT, uuidKey);
        LOG.info("SignIn parameters cached and wctx set to: " + uuidKey + ".");
    }
    
    public void restore(RequestContext context) {
        
        String uuidKey = (String)WebUtils.getAttributeFromFlowScope(context, FederationConstants.PARAM_CONTEXT);
        @SuppressWarnings("unchecked")
        Map<String, Object> signinParams =
            (Map<String, Object>)WebUtils.getAttributeFromExternalContext(context, uuidKey);
        
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
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("SignIn parameters restored: " + signinParams.toString() + ".");
        }
        LOG.info("SignIn parameters restored.");
    }
}