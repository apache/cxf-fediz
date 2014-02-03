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

import javax.security.auth.x500.X500Principal;

import org.apache.cxf.sts.token.realm.SAMLRealmCodec;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SamlRealmCodec implements SAMLRealmCodec {

    private static final Logger LOG = LoggerFactory.getLogger(SamlRealmCodec.class);

    @Override
    public String getRealmFromToken(SamlAssertionWrapper assertion) {
        SAMLKeyInfo ki = assertion.getSignatureKeyInfo();
        X509Certificate[] certs = ki.getCerts();
        X500Principal subject = certs[0].getSubjectX500Principal();
        String name = subject.getName();
        String realm = name.substring(name.indexOf("CN=") + 3);
        LOG.info("Realm parsed in certificate: " + realm);
        return realm.toUpperCase();
    }

}
