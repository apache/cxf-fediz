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

package org.apache.cxf.fediz.core.util;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility methods for validating the AudienceRestriction of a received security token.
 */
public final class AudienceUtils {

    private static final Logger LOG = LoggerFactory.getLogger(AudienceUtils.class);

    private AudienceUtils() {
        // complete
    }

    /**
     * Validate the AudienceRestriction of a received security token (e.g. SAML) against the configured list
     * of audience URIs. A token without an audience is only accepted if no audience URIs are configured, and
     * a token with an audience is only accepted if it matches one of the configured audience URIs.
     *
     * @param audience the audience of the received token (may be null)
     * @param audienceURIs the configured audience URIs
     * @param requestURL the request URL, only used for debug logging (may be null)
     * @return true if the audience is valid for this relying party
     */
    public static boolean validateAudienceRestrictions(String audience, List<String> audienceURIs,
                                                       String requestURL) {
        boolean validAudience = audienceURIs.isEmpty() && audience == null;
        if (!validAudience && audience == null) {
            LOG.warn("Token has no AudienceRestriction but a list of audience URIs is configured.");
        } else if (!validAudience) {
            for (String a : audienceURIs) {
                if (audience.startsWith(a)) {
                    validAudience = true;
                    LOG.debug("Token audience matches with valid URIs.");
                    break;
                }
            }

            if (!validAudience) {
                LOG.warn("Token AudienceRestriction [{}] doesn't match with specified list of URIs.", audience);
                LOG.debug("Authenticated URIs are: {}", audienceURIs);
            }

            if (LOG.isDebugEnabled() && requestURL != null && requestURL.indexOf(audience) == -1) {
                LOG.debug("Token AudienceRestriction doesn't match with request URL [{}]  [{}]", audience, requestURL);
            }
        }
        return validAudience;
    }

}
