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

package org.apache.cxf.fediz.service.sts.realms;

import java.security.Principal;

import org.apache.cxf.sts.IdentityMapper;
import org.apache.wss4j.common.principal.CustomTokenPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A test implementation of IdentityMapper.
 */
public class RealmExtensionIdentityMapper implements IdentityMapper {

    public static final String DEFAULT_DELIMITER = "@";

    private static final Logger LOG = LoggerFactory.getLogger(RealmExtensionIdentityMapper.class);

    private String delimiter = DEFAULT_DELIMITER;

    /**
     * Map a principal in the source realm to the target realm
     * 
     * @param sourceRealm the source realm of the Principal
     * @param sourcePrincipal the principal in the source realm
     * @param targetRealm the target realm of the Principal
     * @return the principal in the target realm
     */
    public Principal mapPrincipal(String sourceRealm, Principal sourcePrincipal, String targetRealm) {
        if (sourcePrincipal == null) {
            return null;
        }

        String name = sourcePrincipal.getName().toLowerCase();
        if (name.contains(delimiter)) {
            // Remove previous realm
            name = name.substring(0, name.indexOf(delimiter));
        }
        // Add target realm
        name = name + getDelimiter() + targetRealm;

        LOG.debug("Principal '{}' mapped to '{}'", sourcePrincipal.getName(), name);

        return new CustomTokenPrincipal(name);
    }

    public String getDelimiter() {
        return delimiter;
    }

    public void setDelimiter(String delimiter) {
        this.delimiter = delimiter;
    }

}
