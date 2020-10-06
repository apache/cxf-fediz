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

package org.apache.cxf.fediz.core.processor;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.servlet.http.HttpServletRequest;

import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.exception.ProcessingException.TYPE;
import org.apache.cxf.fediz.core.spi.IDPCallback;
import org.apache.cxf.fediz.core.spi.RealmCallback;
import org.apache.cxf.fediz.core.spi.ReplyCallback;
import org.apache.cxf.fediz.core.spi.SignInQueryCallback;
import org.apache.cxf.fediz.core.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.net.URLEncoder.encode;
import static java.nio.charset.StandardCharsets.UTF_8;

public abstract class AbstractFedizProcessor implements FedizProcessor {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractFedizProcessor.class);

    protected String resolveIssuer(HttpServletRequest request, FedizContext config) throws IOException,
        UnsupportedCallbackException {
        Object issuerObj = config.getProtocol().getIssuer();
        String issuerURL = null;
        if (issuerObj instanceof String) {
            issuerURL = (String)issuerObj;
        } else if (issuerObj instanceof CallbackHandler) {
            CallbackHandler issuerCB = (CallbackHandler)issuerObj;
            IDPCallback callback = new IDPCallback(request);
            issuerCB.handle(new Callback[] {callback});
            issuerURL = callback.getIssuerUrl().toString();
        }
        return issuerURL;
    }

    protected String resolveWTRealm(HttpServletRequest request, FedizContext config) throws IOException,
        UnsupportedCallbackException {
        Object wtRealmObj = config.getProtocol().getRealm();
        String wtRealm = null;
        if (wtRealmObj != null) {
            if (wtRealmObj instanceof String) {
                wtRealm = (String)wtRealmObj;
            } else if (wtRealmObj instanceof CallbackHandler) {
                CallbackHandler hrCB = (CallbackHandler)wtRealmObj;
                RealmCallback callback = new RealmCallback(request);
                hrCB.handle(new Callback[] {callback});
                wtRealm = callback.getRealm();
            }
        } else {
            wtRealm = extractFullContextPath(request); //default value
        }
        return wtRealm;
    }

    protected void testForReplayAttack(String tokenId, FedizContext config, Instant expires)
        throws ProcessingException {
        // Check whether token already used for signin
        if (tokenId != null && config.isDetectReplayedTokens()) {
            // Check whether token has already been processed once, prevent
            // replay attack
            if (!config.getTokenReplayCache().contains(tokenId)) {
                // not cached
                if (expires != null) {
                    Instant now = Instant.now();
                    long ttl = expires.getEpochSecond() - now.getEpochSecond();
                    config.getTokenReplayCache().add(tokenId, ttl);
                } else {
                    config.getTokenReplayCache().add(tokenId);
                }
            } else {
                LOG.error("Replay attack with token id: " + tokenId);
                throw new ProcessingException("Replay attack with token id: "
                        + tokenId, TYPE.TOKEN_REPLAY);
            }
        }
    }

    protected String extractFullContextPath(HttpServletRequest request) throws MalformedURLException {
        return StringUtils.extractFullContextPath(request);
    }
    
    
    protected List<String> getRoles(List<Claim> claims, String roleURI) {
        if (roleURI == null || roleURI.isEmpty()) {
            return null;
        }
        return getRoles(claims, URI.create(roleURI));
    }

    protected List<String> getRoles(List<Claim> claims, URI roleURI) {
        if (claims == null || roleURI == null) {
            return null;
        }
        List<String> roles = null;
        for (Claim c : claims) {
            if (roleURI.equals(c.getClaimType())) {
                Object oValue = c.getValue();
                if ((oValue instanceof String) && !"".equals(oValue)) {
                    roles = Collections.singletonList((String) oValue);
                } else if ((oValue instanceof List<?>) && !((List<?>) oValue).isEmpty()) {
                    @SuppressWarnings("unchecked")
                    List<String> values = (List<String>) oValue;
                    roles = Collections.unmodifiableList(values);
                } else if (!((oValue instanceof String) || (oValue instanceof List<?>))) {
                    LOG.error("Unsupported value type of Claim value");
                    throw new IllegalStateException("Unsupported value type of Claim value");
                }
                break;
            }
        }
        return roles;
    }
    
    protected String resolveReply(HttpServletRequest request, FedizContext config) throws IOException,
        UnsupportedCallbackException {
        Object replyObj = config.getProtocol().getReply();
        String reply = null;
        if (replyObj != null) {
            if (replyObj instanceof String) {
                reply = (String)replyObj;
            } else if (replyObj instanceof CallbackHandler) {
                CallbackHandler replyCB = (CallbackHandler)replyObj;
                ReplyCallback callback = new ReplyCallback(request);
                replyCB.handle(new Callback[] {
                    callback
                });
                reply = callback.getReply();
            }
        }
        return reply;
    }

    protected void testForMandatoryClaims(String roleURI,
                                        List<org.apache.cxf.fediz.core.config.Claim> requestedClaims,
                                        List<org.apache.cxf.fediz.core.Claim> receivedClaims
    ) throws ProcessingException {
        if (requestedClaims != null) {
            for (org.apache.cxf.fediz.core.config.Claim requestedClaim : requestedClaims) {
                if (!requestedClaim.isOptional()) {
                    boolean found = false;
                    for (org.apache.cxf.fediz.core.Claim receivedClaim : receivedClaims) {
                        if (requestedClaim.getType().equals(receivedClaim.getClaimType().toString())) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        LOG.warn("Mandatory claim {} not found in token", requestedClaim.getType());
                        throw new ProcessingException("Mandatory claim not found in token", TYPE.INVALID_REQUEST);
                    }
                }
            }
        }
    }

    protected String resolveSignInQuery(HttpServletRequest request, FedizContext config) throws IOException,
            UnsupportedCallbackException {
        Object signInQueryObj = config.getProtocol().getSignInQuery();
        String signInQuery = null;
        if (signInQueryObj != null) {
            if (signInQueryObj instanceof String) {
                signInQuery = (String)signInQueryObj;
            } else if (signInQueryObj instanceof CallbackHandler) {
                CallbackHandler frCB = (CallbackHandler)signInQueryObj;
                SignInQueryCallback callback = new SignInQueryCallback(request);
                frCB.handle(new Callback[] {callback});
                Map<String, String> signInQueryMap = callback.getSignInQueryParamMap();
                if (signInQueryMap != null) {
                    StringBuilder sbQuery = new StringBuilder();
                    for (Map.Entry<String, String> entry : signInQueryMap.entrySet()) {
                        if (sbQuery.length() > 0) {
                            sbQuery.append('&');
                        }
                        sbQuery.append(entry.getKey()).append('=').append(encode(entry.getValue(), UTF_8.name()));
                    }
                    signInQuery = sbQuery.toString();
                }

            }
        }
        return signInQuery;
    }
}
