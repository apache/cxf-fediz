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
package org.apache.cxf.fediz.service.oidc;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import org.apache.cxf.common.util.PropertyUtils;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.jaxrs.utils.JAXRSUtils;
import org.apache.cxf.message.Message;
import org.apache.cxf.rs.security.jose.common.JoseConstants;
import org.apache.cxf.rs.security.jose.common.JoseException;
import org.apache.cxf.rs.security.jose.common.KeyManagementUtils;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKeys;
import org.apache.cxf.rs.security.jose.jwk.JwkUtils;
import org.apache.cxf.rs.security.jose.jwk.KeyOperation;
import org.apache.cxf.rs.security.jose.jwk.KeyType;
import org.apache.cxf.rs.security.jose.jwk.PublicKeyUse;
import org.apache.cxf.rs.security.jose.jws.JwsUtils;

/**
 * TODO Remove this once we pick up CXF 3.3.5
 */
@Path("keys")
public class FedizOidcKeysService {

    private volatile JsonWebKeys keySet;
    private WebClient keyServiceClient;
    private boolean stripPrivateParameters = true;

    @GET
    @Produces("application/json")
    public JsonWebKeys getPublicVerificationKeys() {
        if (keySet == null) {
            if (keyServiceClient == null) {
                keySet = getFromLocalStore(stripPrivateParameters);
            } else {
                keySet = keyServiceClient.get(JsonWebKeys.class);
            }

        }
        return keySet;
    }

    private static JsonWebKeys getFromLocalStore(boolean stripPrivateParameters) {
        Properties props = JwsUtils.loadSignatureInProperties(true);
        return loadPublicVerificationKeys(JAXRSUtils.getCurrentMessage(), props, stripPrivateParameters);
    }

    public void setKeyServiceClient(WebClient keyServiceClient) {
        this.keyServiceClient = keyServiceClient;
    }

    public boolean isStripPrivateParameters() {
        return stripPrivateParameters;
    }

    /**
     * Whether to strip private parameters from the keys that are returned. The default is true.
     */
    public void setStripPrivateParameters(boolean stripPrivateParameters) {
        this.stripPrivateParameters = stripPrivateParameters;
    }
    
    private static JsonWebKeys loadPublicVerificationKeys(Message m, Properties props, boolean stripPrivateParameters) {
        String storeType = props.getProperty(JoseConstants.RSSEC_KEY_STORE_TYPE);
        if ("jwk".equals(storeType)) {
            List<JsonWebKey> jsonWebKeys = loadJsonWebKeys(m, props, KeyOperation.SIGN);
            if (jsonWebKeys == null || jsonWebKeys.isEmpty()) {
                throw new JoseException("Error loading keys");
            }
            JsonWebKeys retKeys = new JsonWebKeys();
            retKeys.setKeys(stripPrivateParameters ?  stripPrivateParameters(jsonWebKeys) : jsonWebKeys);
            return retKeys;
        }
        X509Certificate[] certs = null;
        if (PropertyUtils.isTrue(props.get(JoseConstants.RSSEC_SIGNATURE_INCLUDE_CERT))) {
            certs = KeyManagementUtils.loadX509CertificateOrChain(m, props);
        }
        PublicKey key = certs != null && certs.length > 0
            ? certs[0].getPublicKey() : KeyManagementUtils.loadPublicKey(m, props);
        JsonWebKey jwk = JwkUtils.fromPublicKey(key, props, JoseConstants.RSSEC_SIGNATURE_ALGORITHM);
        jwk.setPublicKeyUse(PublicKeyUse.SIGN);
        if (certs != null) {
            jwk.setX509Chain(KeyManagementUtils.encodeX509CertificateChain(certs));
        }
        return new JsonWebKeys(jwk);
    }

    private static List<JsonWebKey> stripPrivateParameters(List<JsonWebKey> keys) {
        if (keys == null) {
            return Collections.emptyList();
        }

        List<JsonWebKey> parsedKeys = new ArrayList<>(keys.size());
        Iterator<JsonWebKey> iter = keys.iterator();
        while (iter.hasNext()) {
            JsonWebKey key = iter.next();
            if (!(key.containsProperty("k") || key.getKeyType() == KeyType.OCTET)) {
                // We don't allow secret keys in a public keyset
                key.removeProperty(JsonWebKey.RSA_PRIVATE_EXP);
                key.removeProperty(JsonWebKey.RSA_FIRST_PRIME_FACTOR);
                key.removeProperty(JsonWebKey.RSA_SECOND_PRIME_FACTOR);
                key.removeProperty(JsonWebKey.RSA_FIRST_PRIME_CRT);
                key.removeProperty(JsonWebKey.RSA_SECOND_PRIME_CRT);
                key.removeProperty(JsonWebKey.RSA_FIRST_CRT_COEFFICIENT);
                parsedKeys.add(key);
            }
        }
        return parsedKeys;
    }
    
    private static List<JsonWebKey> loadJsonWebKeys(Message m,
                                                   Properties props,
                                                   KeyOperation keyOper) {
        JsonWebKeys jwkSet = JwkUtils.loadJwkSet(m, props, null);
        String kid = KeyManagementUtils.getKeyId(m, props, JoseConstants.RSSEC_KEY_STORE_ALIAS, keyOper);
        if (kid != null) {
            return Collections.singletonList(jwkSet.getKey(kid));
        }
        String kids = KeyManagementUtils.getKeyId(m, props, JoseConstants.RSSEC_KEY_STORE_ALIASES, keyOper);
        if (kids != null) {
            String[] values = kids.split(",");
            List<JsonWebKey> keys = new ArrayList<>(values.length);
            for (String value : values) {
                keys.add(jwkSet.getKey(value));
            }
            return keys;
        }
        if (keyOper != null) {
            List<JsonWebKey> keys = jwkSet.getKeyOperationMap().get(keyOper);
            if (keys != null && keys.size() == 1) {
                return Collections.singletonList(keys.get(0));
            }
        }
        return null;
    }
}
