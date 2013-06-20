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

package org.apache.cxf.fediz.cxf.web;


import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.w3c.dom.Element;

import org.apache.cxf.fediz.core.SecurityTokenThreadLocal;
import org.apache.cxf.ws.security.trust.delegation.DelegationCallback;
import org.apache.ws.security.util.DOM2Writer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This CallbackHandler implementation obtains the security token from
 * the thread local storage to be used as the delegation token.
 */ 
public class ThreadLocalCallbackHandler implements CallbackHandler {

    private static final Logger LOG = LoggerFactory.getLogger(ThreadLocalCallbackHandler.class);


    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof DelegationCallback) {
                DelegationCallback callback = (DelegationCallback) callbacks[i];
                Element token = SecurityTokenThreadLocal.getToken();
                if (token == null) {
                    LOG.error("Security token not cached in thread local storage. Check configuration");
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("******************** TOKEN ********************");
                        LOG.debug(DOM2Writer.nodeToString(token));
                        LOG.debug("****************** END TOKEN *******************");
                    }
                    callback.setToken(token);     
                }

            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }

}
