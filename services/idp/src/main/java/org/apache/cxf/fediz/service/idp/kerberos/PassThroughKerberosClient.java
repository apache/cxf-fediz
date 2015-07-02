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

package org.apache.cxf.fediz.service.idp.kerberos;

import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.cxf.ws.security.kerberos.KerberosClient;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.message.token.KerberosSecurity;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.utils.Base64;

/**
 * Override the default CXF KerberosClient just to create a BinarySecurityToken from a 
 * give Kerberos token. This is used to pass a received Kerberos token through to the 
 * STS, without retrieving a new token.
 */
public class PassThroughKerberosClient extends KerberosClient {
    
    private byte[] token;

    public PassThroughKerberosClient() {
        super();
    }

    @Override
    public SecurityToken requestSecurityToken() throws Exception {
        KerberosSecurity bst = new KerberosSecurity(DOMUtils.createDocument());
        bst.setValueType(WSConstants.WSS_GSS_KRB_V5_AP_REQ);
        bst.setToken(token);
        bst.addWSUNamespace();
        bst.setID(WSSConfig.getNewInstance().getIdAllocator().createSecureId("BST-", bst));
        
        SecurityToken securityToken = new SecurityToken(bst.getID());
        securityToken.setToken(bst.getElement());
        securityToken.setWsuId(bst.getID());
        String sha1 = Base64.encode(WSSecurityUtil.generateDigest(bst.getToken()));
        securityToken.setSHA1(sha1);
        securityToken.setTokenType(bst.getValueType());

        return securityToken;
    }

    public byte[] getToken() {
        return token;
    }

    public void setToken(byte[] token) {
        this.token = token;
    }

}
