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

import java.util.regex.Matcher;

import org.apache.cxf.fediz.service.idp.domain.Application;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

/**
 * This class is responsible to validate the 'wreply' parameter for WS-Federation, or else the
 * AssertionConsumer URL address for SAML SSO, by comparing it to a regular expression.
 */
@Component
public class PassiveRequestorValidator {

    private static final Logger LOG = LoggerFactory.getLogger(PassiveRequestorValidator.class);

    public boolean isValid(RequestContext context, String endpointAddress, String realm)
        throws Exception {
        if (endpointAddress == null) {
            return true;
        }

        Idp idpConfig = (Idp) WebUtils.getAttributeFromFlowScope(context, "idpConfig");
        Application serviceConfig = idpConfig.findApplication(realm);
        if (serviceConfig == null) {
            LOG.warn("No service config found for " + realm);
            return false;
        }

        if (serviceConfig.getPassiveRequestorEndpoint() == null
            && serviceConfig.getCompiledPassiveRequestorEndpointConstraint() == null) {
            LOG.error("Either the 'passiveRequestorEndpoint' or the 'passiveRequestorEndpointConstraint' "
                + "configuration values must be specified for the application");
        } else if (serviceConfig.getPassiveRequestorEndpoint() != null
            && serviceConfig.getPassiveRequestorEndpoint().equals(endpointAddress)) {
            LOG.debug("The supplied endpoint address {} matches the configured passive requestor endpoint value",
                      endpointAddress);
            return true;
        } else if (serviceConfig.getCompiledPassiveRequestorEndpointConstraint() != null) {
            Matcher matcher =
                serviceConfig.getCompiledPassiveRequestorEndpointConstraint().matcher(endpointAddress);
            if (matcher.matches()) {
                return true;
            } else {
                LOG.error("The endpointAddress value of {} does not match any of the passive requestor values",
                          endpointAddress);
            }
        }

        return false;
    }

}
