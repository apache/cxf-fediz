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
import java.net.URL;
import java.util.Date;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.servlet.http.HttpServletRequest;

import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.exception.ProcessingException.TYPE;
import org.apache.cxf.fediz.core.spi.IDPCallback;
import org.apache.cxf.fediz.core.spi.RealmCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    
    protected void testForReplayAttack(String tokenId, FedizContext config, Date expires) 
        throws ProcessingException {
        // Check whether token already used for signin
        if (tokenId != null && config.isDetectReplayedTokens()) {
            // Check whether token has already been processed once, prevent
            // replay attack
            if (!config.getTokenReplayCache().contains(tokenId)) {
                // not cached
                if (expires != null) {
                    Date currentTime = new Date();
                    long ttl = expires.getTime() - currentTime.getTime();
                    config.getTokenReplayCache().add(tokenId, ttl / 1000L);
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
        String result = null;
        String contextPath = request.getContextPath();
        String requestUrl = request.getRequestURL().toString();
        String requestPath = new URL(requestUrl).getPath();
        // Cut request path of request url and add context path if not ROOT
        if (requestPath != null && requestPath.length() > 0) {
            int lastIndex = requestUrl.lastIndexOf(requestPath);
            result = requestUrl.substring(0, lastIndex);
        } else {
            result = requestUrl;
        }
        if (contextPath != null && contextPath.length() > 0) {
            // contextPath contains starting slash
            result = result + contextPath + "/";
        } else {
            result = result + "/";
        }
        return result;
    }
    
}
