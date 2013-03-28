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

import java.util.Date;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is responsible to parse 'wfresh' parameter 
 * @author T.Beucher 
 */

public class WfreshParser {

    private static final Logger LOG = LoggerFactory
            .getLogger(WfreshParser.class);

    public boolean authenticationRequired(SecurityToken idpToken, String wfresh)
        throws Exception {
        long ttl = Long.parseLong(wfresh);
        if (ttl > 0) {
            Date createdDate = idpToken.getCreated();
            Date expiryDate = new Date();
            expiryDate.setTime(createdDate.getTime() + (ttl * 60L * 1000L));
            if (expiryDate.before(new Date())) {
                LOG.info("IDP token is valid but relying party requested new authentication via wfresh: " + wfresh);
                return true;
            }
        } else {
            LOG.info("wfresh value of " + wfresh + " is invalid");
        }
        return false;
    }
}
