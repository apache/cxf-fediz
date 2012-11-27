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

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public abstract class AbstractAuthFilter implements Filter {

    public static final String PRE_STATE = "pre-state";
    public static final String NEXT_STATE = "next-state";
    public static final String PROCESSING_STATE = "processing-state";
    
    //@SuppressWarnings("PMD")
    //protected static Logger LOG;
    private static final Logger LOG = LoggerFactory.getLogger(AbstractAuthFilter.class);

    // String used because of custom states, state set during processing time are stored in AuthContext
    private String preState;
    private String nextState;

    enum ProcessingState {
        CONTINUE,
        SEND_RESPONSE
    }
    
    public void setNextState(String state, AuthContext context) {
        context.put(NEXT_STATE, state);
    }
    
    public String getNextState(AuthContext context, boolean remove) {
        String updatedNextState = (String)context.get(NEXT_STATE);
        if (updatedNextState != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("next-state [" + updatedNextState + "] overwritten by filter");
            }
            if (remove) {
                context.remove(NEXT_STATE);
            }
            return updatedNextState;
        } else {
            return nextState;
        }
    }
    
    public String getNextState(AuthContext context) {
        return getNextState(context, false);
    }
    

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        preState = filterConfig.getInitParameter(PRE_STATE);
        if (LOG.isDebugEnabled()) {
            if (preState == null) {
                LOG.debug("Parameter '" + PRE_STATE + "' not defined");
            } else {
                LOG.debug("Parameter '" + PRE_STATE + "' set to [" + preState + "]");
            }
        }
        
        nextState = filterConfig.getInitParameter(NEXT_STATE);
        if (LOG.isDebugEnabled()) {
            if (nextState == null) {
                LOG.debug("Parameter '" + NEXT_STATE + "' not defined");
            } else {
                LOG.debug("Parameter '" + NEXT_STATE + "' set to [" + nextState + "]");
            }
        }

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest hrequest = null;
        if (request instanceof HttpServletRequest) {
            hrequest = (HttpServletRequest)request;
        } else {
            throw new IllegalStateException("ServletRequest not of type HttpServletRequest");
        }
        HttpSession session = (HttpSession)hrequest.getSession(true);
        AuthContext context = new AuthContext(session, hrequest);
        
        String currentState = null;
        if (context.get(AuthContext.CURRENT_STATE) == null) {
            currentState = States.NOT_AUTHENTICATED.toString();
            context.put(AuthContext.CURRENT_STATE, currentState);
            LOG.info("No state defined. Defaulting to [" + States.NOT_AUTHENTICATED.toString() + "]");
        } else {
            currentState = (String)context.get(AuthContext.CURRENT_STATE);
            LOG.info("Current state: " + currentState);
        }
        if (preState == null) {
            LOG.info("No pre-state defined. State condition ignored");
            //throw new IllegalStateException("No pre-state defined");
        }
        if (preState == null || preState.equals(currentState)) {
            if (preState == null) {
                LOG.info("No pre-state defined. State condition ignored");
            } else {
                LOG.info("State condition met for " + this.getClass().getName());
            }
            try {
                this.process(hrequest, (HttpServletResponse)response, context);
                String resolvedNextState = getNextState(context, true);
                if (resolvedNextState != null) {
                    context.put(AuthContext.CURRENT_STATE, resolvedNextState);
                    LOG.info("State changed to [" + resolvedNextState + "]");
                } else {
                    LOG.info("State remains at [" + currentState + "]");
                }
            } catch (ProcessingException ex) {
                LOG.info("ProcessingException occured. Sending repsonse.");
                //response message prepared by underlying filter, error code
                return;
            }
        } else {
            LOG.debug("State condition not met for " + this.getClass().getName() + ". Ignored."); 
        }
        if (context.get(PROCESSING_STATE) == null
            || ProcessingState.CONTINUE.equals((ProcessingState)context.get(PROCESSING_STATE))) {
            chain.doFilter(request, response);
        } else {
            LOG.info("Processing aborted. Invalidate session. Sending response.");
            //session.invalidate(); //why???
            //context.remove(PROCESSING_STATE); //why???
        }
        
        if (hrequest.getSession(false) != null) {
            context.put(AuthContext.CURRENT_STATE, context.get(AuthContext.CURRENT_STATE), true);
            
            if (context.get(AuthContext.INVALIDATE_SESSION) != null
                && Boolean.TRUE.equals((Boolean)context.get(AuthContext.INVALIDATE_SESSION))) {
                context.remove(AuthContext.INVALIDATE_SESSION);
                session.invalidate();
                LOG.info("Session invalidated");
            }
        }
        
        
    }

    @Override
    public void destroy() {

    }

    public abstract void process(HttpServletRequest request, HttpServletResponse response, AuthContext context)
        throws IOException, ServletException, ProcessingException;


}
