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

package org.apache.cxf.fediz.service.idp.protocols;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.cxf.jaxrs.json.basic.JsonMapObject;
import org.apache.wss4j.common.saml.bean.AttributeBean;
import org.apache.wss4j.common.saml.bean.AttributeStatementBean;
import org.apache.wss4j.common.saml.builder.SAML2Constants;

/**
 * Convert a "role" claim into a SAML AttributeStatement
 */
public class RoleClaimsHandler implements ClaimsHandler {
    
    private static final URI ROLE =
        URI.create("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role");
    private String nameFormat = SAML2Constants.ATTRNAME_FORMAT_UNSPECIFIED;

    public AttributeStatementBean handleClaims(JsonMapObject claims) {
        if (claims != null) {
            String role = claims.getStringProperty("role");
            if (role != null) {
                AttributeStatementBean attrBean = new AttributeStatementBean();
                AttributeBean attributeBean = new AttributeBean();
                attributeBean.setQualifiedName(ROLE.toString());
                attributeBean.setNameFormat(nameFormat);
                List<Object> attributes = new ArrayList<>();
                attributes.add(role);
                attributeBean.setAttributeValues(attributes);
                attrBean.setSamlAttributes(Collections.singletonList(attributeBean));
                return attrBean;
            }
        }

        return null;
    }

}
