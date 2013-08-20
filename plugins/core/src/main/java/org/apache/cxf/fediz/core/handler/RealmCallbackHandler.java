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
package org.apache.cxf.fediz.core.handler;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.spi.RealmCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RealmCallbackHandler implements CallbackHandler {

    private static final Logger LOG = LoggerFactory.getLogger(RealmCallbackHandler.class);

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof RealmCallback) {
                RealmCallback callback = (RealmCallback) callbacks[i];
                String param = FederationConstants.PARAM_TREALM;
                String wtRealm = (String)callback.getRequest().getAttribute(param);
                if (wtRealm == null || wtRealm.length() == 0) {
                    LOG.debug("No wtrealm found in request");
                } else {
                    LOG.info("WTRealm '" + wtRealm + "' found in request");
                    callback.setRealm(wtRealm);
                }
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }
}