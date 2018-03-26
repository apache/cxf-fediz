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

import javax.servlet.http.HttpServletRequest;

import org.apache.cxf.fediz.service.idp.spi.ApplicationProtocolHandler;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

@Component
public class ApplicationWSFedProtocolHandler implements ApplicationProtocolHandler {

    public static final String PROTOCOL = "http://docs.oasis-open.org/wsfed/federation/200706";

    //private static final Logger LOG = LoggerFactory.getLogger(ApplicationWSFedProtocolHandler.class);

    @Override
    public boolean canHandleRequest(HttpServletRequest request) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public String getProtocol() {
        return PROTOCOL;
    }

    @Override
    public void mapSignInRequest(RequestContext context) {
        // TODO Auto-generated method stub
    }

    @Override
    public void mapSignInResponse(RequestContext context) {
        // TODO Auto-generated method stub
    }

}
