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
package org.apache.cxf.fediz.service.idp.beans.wsfed;

import java.util.regex.Matcher;

import org.apache.commons.validator.routines.UrlValidator;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.exception.ProcessingException.TYPE;
import org.apache.cxf.fediz.service.idp.domain.Application;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

/**
 * This class is responsible to validate the 'wreply' parameter 
 */
@Component
public class WreplyValidator {

    private static final Logger LOG = LoggerFactory.getLogger(WreplyValidator.class);

    public boolean isValid(RequestContext context, String wreply, String realm)
        throws Exception {
        if (wreply == null) {
           return true;
        }
        
        Idp idpConfig = (Idp) WebUtils.getAttributeFromFlowScope(context, "idpConfig");
        Application serviceConfig = idpConfig.findApplication(realm);
        if (serviceConfig == null) {
            LOG.warn("No service config found for " + realm);
            return true;
        }
        
        // The wreply address must match the passive endpoint requestor constraint (if it is specified)
        // Also, it must be a valid URL + start with https
        // Validate it first using commons-validator
        UrlValidator urlValidator = new UrlValidator(UrlValidator.ALLOW_LOCAL_URLS
                                                     + UrlValidator.ALLOW_ALL_SCHEMES);
        if (!urlValidator.isValid(wreply)) {
            LOG.warn("The given wreply parameter {} is not a valid URL", wreply);
            return false;
        }

        if (serviceConfig.getCompiledPassiveRequestorEndpointConstraint() == null) {
            LOG.warn("No passive requestor endpoint constraint is configured for the application. "
                + "This could lead to a malicious redirection attack");
            return true;
        }

        Matcher matcher = serviceConfig.getCompiledPassiveRequestorEndpointConstraint().matcher(wreply);
        if (!matcher.matches()) {
            LOG.error("The wreply value of {} does not match any of the passive requestor values",
                      wreply);
            return false;
        }
        
        return true;
    }
    
}
