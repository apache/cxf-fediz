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
package org.apache.cxf.fediz.service.idp;

import java.io.IOException;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LogoutFilter extends AbstractAuthFilter {

    public static final String PARAM_LOGOUT_URI = "logout.uri";
    
    private static final Logger LOG = LoggerFactory.getLogger(LogoutFilter.class);

    private String logoutUri;
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        super.init(filterConfig);
        
        logoutUri = filterConfig.getInitParameter(PARAM_LOGOUT_URI);
        if (logoutUri != null && logoutUri.length() > 0) {
            LOG.info("Configured logout URI: " + logoutUri);
        }
    }
    
    @Override
    public void process(HttpServletRequest request,
                        HttpServletResponse response, AuthContext context)
        throws IOException, ServletException, ProcessingException {

        if (request.getParameter(this.logoutUri) != null) {
            HttpSession session = request.getSession(false);
            if (session == null) {
                LOG.info("Logout ignored. No session available.");
                return;
            }
            
            LOG.info("Logout session for '" + context.get(AuthContext.IDP_PRINCIPAL) + "'");
            context.put(AuthContext.INVALIDATE_SESSION, Boolean.TRUE);
            //Session invalidation occurs in AbstractAuthFilter due to session access for
            //State management
            //session.invalidate();
            this.setNextState(States.NOT_AUTHENTICATED.toString(), context);
            context.put(AbstractAuthFilter.PROCESSING_STATE, AbstractAuthFilter.ProcessingState.SEND_RESPONSE);
        }
        
    }

}
