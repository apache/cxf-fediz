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

import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.RequestContext;

/**
 * @author fr17993 This class is responsible to initialize web flow.
 */

public class InitialFlowSetupAction {

    private static final String AUTH_SUPPORT_TYPE = "idp.authSupportType";

    private static final String IDP_NAME = "idpName";

    private static final Logger LOG = LoggerFactory
            .getLogger(InitialFlowSetupAction.class);

    private String idpName = "IDP";

    private String authSupportType;

    public String getIdpName() {
        return idpName;
    }

    public void setIdpName(String idpName) {
        this.idpName = idpName;
    }

    public String getAuthSupportType() {
        return authSupportType;
    }

    public void setAuthSupportType(String authSupportType) {
        this.authSupportType = authSupportType;
    }

    private static enum SupportType {
        FORM, BASIC;
    }

    /**
     * @throws IllegalArgumentException
     */
    public void submit(RequestContext context) {
        if (System.getProperty(AUTH_SUPPORT_TYPE) != null) {
            authSupportType = System.getProperty(AUTH_SUPPORT_TYPE);
            LOG.info("Bean property [authSupportType] has been overriden from system properties");
        }
        if (SupportType.valueOf(authSupportType) != null) {
            WebUtils.putAttributeInFlowScope(context, AUTH_SUPPORT_TYPE,
                    authSupportType);
            LOG.info(AUTH_SUPPORT_TYPE + "=" + authSupportType
                    + " has been stored in flow scope");
        } else {
            throw new IllegalArgumentException(AUTH_SUPPORT_TYPE + "="
                    + authSupportType + " not supported");
        }
        putAttributeInFlowScope(context, IDP_NAME, idpName);
    }

    private void putAttributeInFlowScope(RequestContext context, String key, String value) {
        if (value != null) {
            WebUtils.putAttributeInFlowScope(context, key, value);
            LOG.info(key + "=" + value + " has been stored in flow scope");
        } else {
            throw new IllegalArgumentException("Bean property [" + key + "] should be configured");
        }
    }
}
