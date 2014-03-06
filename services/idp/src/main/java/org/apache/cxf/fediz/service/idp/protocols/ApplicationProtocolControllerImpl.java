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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.cxf.fediz.service.idp.spi.ApplicationProtocolHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class ApplicationProtocolControllerImpl implements ProtocolController<ApplicationProtocolHandler> {

    private static final Logger LOG = LoggerFactory.getLogger(ApplicationProtocolControllerImpl.class);
    
    @Autowired
    private List<ApplicationProtocolHandler> protocolHandlers;
    
    @Override
    public ApplicationProtocolHandler getProtocolHandler(String protocol) {
        for (ApplicationProtocolHandler protocolHandler : protocolHandlers) {
            if (protocolHandler.equals(protocol)) {
                return protocolHandler;
            }
        }
        LOG.warn("No protocol handler found for {}", protocol);
        return null;
    }
    
    @Override
    public List<String> getProtocols() {
        List<String> protocols = new ArrayList<String>();
        for (ApplicationProtocolHandler protocolHandler : protocolHandlers) {
            protocols.add(protocolHandler.getProtocol());
        }
        return Collections.unmodifiableList(protocols);
    }

}
