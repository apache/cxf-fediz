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

import java.security.cert.X509Certificate;

import org.apache.cxf.sts.token.realm.SAMLRealmCodec;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SamlRealmCodec implements SAMLRealmCodec {

    private static final Logger LOG = LoggerFactory.getLogger(SamlRealmCodec.class);

    private boolean uppercase = true;

    @Override
    public String getRealmFromToken(SamlAssertionWrapper assertion) {
        SAMLKeyInfo ki = assertion.getSignatureKeyInfo();
        X509Certificate[] certs = ki.getCerts();
        String realm = parseCNValue(certs[0].getSubjectX500Principal().getName());
        LOG.info("Realm parsed in certificate: " + realm);
        return realm;
    }

    protected String parseCNValue(String name) {
        int len = name.indexOf(',') > 0 ? name.indexOf(',') : name.length();
        String realm = name.substring(name.indexOf("CN=") + 3, len);

        if (uppercase) {
            realm = realm.toUpperCase();
        }
        return realm;
    }

    public boolean isUppercase() {
        return uppercase;
    }

    public void setUppercase(boolean uppercase) {
        this.uppercase = uppercase;
    }

}
