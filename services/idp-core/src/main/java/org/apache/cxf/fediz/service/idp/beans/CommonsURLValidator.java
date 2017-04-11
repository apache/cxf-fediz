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

import java.util.Arrays;
import java.util.List;

import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.DomainValidator.ArrayType;
import org.apache.commons.validator.routines.UrlValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.RequestContext;

/**
 * Validate a URL using Commons Validator
 */
public class CommonsURLValidator {

    private static final Logger LOG = LoggerFactory.getLogger(CommonsURLValidator.class);

    public boolean isValid(RequestContext context, String endpointAddress)
        throws Exception {
        if (endpointAddress == null) {
            return true;
        }

        // The endpointAddress address must be a valid URL + start with http(s)
        // Validate it first using commons-validator
        UrlValidator urlValidator = new UrlValidator(new String[] {"http", "https"}, UrlValidator.ALLOW_LOCAL_URLS);
        if (!urlValidator.isValid(endpointAddress)) {
            LOG.warn("The given endpointAddress parameter {} is not a valid URL", endpointAddress);
            return false;
        }

        return true;
    }

    public void setAdditionalTLDs(List<String> additionalTLDs) {
        // Support additional top level domains
        if (additionalTLDs != null && !additionalTLDs.isEmpty()) {
            try {
                String[] tldsToAddArray = additionalTLDs.toArray(new String[additionalTLDs.size()]);
                LOG.info("Adding the following additional Top Level Domains: " + Arrays.toString(tldsToAddArray));
                DomainValidator.updateTLDOverride(ArrayType.GENERIC_PLUS, tldsToAddArray);
            } catch (IllegalStateException ex) {
                //
            }
        }
    }
}
