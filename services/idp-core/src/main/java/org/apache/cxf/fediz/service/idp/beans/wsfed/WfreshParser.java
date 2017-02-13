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

import java.util.Date;

import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

/**
 * This class is responsible to parse the 'wfresh' parameter
 */
@Component
public class WfreshParser {

    private static final Logger LOG = LoggerFactory.getLogger(WfreshParser.class);

    public boolean authenticationRequired(String wfresh, String whr, RequestContext context)
        throws Exception {

        SecurityToken idpToken =
            (SecurityToken) WebUtils.getAttributeFromExternalContext(context, whr);
        if (idpToken == null) {
            return true;
        }

        if (wfresh == null || wfresh.trim().isEmpty()) {
            return false;
        }

        long ttl;
        try {
            ttl = Long.parseLong(wfresh.trim());
        } catch (Exception e) {
            LOG.info("wfresh value '" + wfresh + "' is invalid.");
            return false;
        }
        if (ttl == 0) {
            return true;
        }

        long ttlMs = ttl * 60L * 1000L;
        if (ttlMs > 0) {
            Date createdDate = idpToken.getCreated();
            if (createdDate != null) {
                Date expiryDate = new Date();
                expiryDate.setTime(createdDate.getTime() + ttlMs);
                if (expiryDate.before(new Date())) {
                    LOG.info("[IDP_TOKEN="
                            + idpToken.getId()
                            + "] is valid but relying party requested new authentication caused by wfresh="
                            + wfresh + " outdated.");
                    return true;
                }
            } else {
                LOG.info("token creation date not set. Unable to check wfresh is outdated.");
            }
        } else {
            LOG.info("ttl value '" + ttl + "' is negative or is too large.");
        }
        return false;
    }

}
