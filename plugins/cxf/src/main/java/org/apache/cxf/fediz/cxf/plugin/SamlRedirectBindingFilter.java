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
package org.apache.cxf.fediz.cxf.plugin;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.SAMLSSOConstants;
import org.apache.cxf.fediz.core.config.FederationProtocol;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.config.SAMLProtocol;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.processor.FedizProcessor;
import org.apache.cxf.fediz.core.processor.FedizProcessorFactory;
import org.apache.cxf.fediz.core.processor.FedizRequest;
import org.apache.cxf.fediz.core.processor.FedizResponse;
import org.apache.cxf.fediz.core.processor.RedirectionResponse;
import org.apache.cxf.fediz.core.samlsso.ResponseState;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.jaxrs.impl.UriInfoImpl;
import org.apache.cxf.jaxrs.utils.ExceptionUtils;
import org.apache.cxf.jaxrs.utils.JAXRSUtils;
import org.apache.cxf.message.Message;
import org.apache.wss4j.common.util.DOM2Writer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SamlRedirectBindingFilter extends AbstractServiceProviderFilter {
    
    private static final Logger LOG = LoggerFactory.getLogger(SamlRedirectBindingFilter.class);
    
    @Context 
    private MessageContext messageContext;
    
    public void filter(ContainerRequestContext context) {
        Message m = JAXRSUtils.getCurrentMessage();
        if (checkSecurityContext(m)) {
            return;
        } else {
            try {
                FedizContext fedConfig = getFedizContext(m);
                if (isSignInRequired(context, fedConfig)) {
                    // Unauthenticated -> redirect
                    FedizProcessor processor = 
                        FedizProcessorFactory.newFedizProcessor(fedConfig.getProtocol());

                    HttpServletRequest request = messageContext.getHttpServletRequest();
                    RedirectionResponse redirectionResponse = 
                        processor.createSignInRequest(request, fedConfig);
                    String redirectURL = redirectionResponse.getRedirectionURL();
                    if (redirectURL != null) {
                        ResponseBuilder response = Response.seeOther(new URI(redirectURL));
                        Map<String, String> headers = redirectionResponse.getHeaders();
                        if (!headers.isEmpty()) {
                            for (String headerName : headers.keySet()) {
                                response.header(headerName, headers.get(headerName));
                            }
                        }

                        context.abortWith(response.build());
                    } else {
                        LOG.warn("Failed to create SignInRequest.");
                        throw ExceptionUtils.toInternalServerErrorException(null, null);
                    }
                } else if (isSignInRequest(context, fedConfig)) {
                    String responseToken = getResponseToken(context, fedConfig);
                    
                    if (responseToken == null) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("SignIn request must contain a response token from the IdP");
                        }
                        throw ExceptionUtils.toBadRequestException(null, null);
                    } else {
                        // processSignInRequest
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Process SignIn request");
                            LOG.debug("token=\n" + responseToken);
                        }

                        FedizRequest wfReq = new FedizRequest();
                        MultivaluedMap<String, String> params = context.getUriInfo().getQueryParameters();
                        wfReq.setAction(params.getFirst(FederationConstants.PARAM_ACTION));
                        wfReq.setResponseToken(responseToken);
                        wfReq.setState(params.getFirst("RelayState"));
                        HttpServletRequest request = messageContext.getHttpServletRequest();
                        wfReq.setRequest(request);
                        
                        X509Certificate certs[] = 
                            (X509Certificate[])request.getAttribute("javax.servlet.request.X509Certificate");
                        wfReq.setCerts(certs);

                        FedizProcessor wfProc = 
                            FedizProcessorFactory.newFedizProcessor(fedConfig.getProtocol());
                        FedizResponse wfRes = null;
                        try {
                            wfRes = wfProc.processRequest(wfReq, fedConfig);
                        } catch (ProcessingException ex) {
                            LOG.error("Federation processing failed: " + ex.getMessage());
                            throw ExceptionUtils.toNotAuthorizedException(ex, null);
                        }
                        
                        // Validate AudienceRestriction
                        List<String> audienceURIs = fedConfig.getAudienceUris();
                        validateAudienceRestrictions(wfRes, audienceURIs, request);

                        // Set the security context
                        String securityContextKey = UUID.randomUUID().toString();
                           
                        SAMLProtocol protocol = (SAMLProtocol)fedConfig.getProtocol();
                        
                        long currentTime = System.currentTimeMillis();
                        Date notOnOrAfter =  wfRes.getTokenExpires();
                        long expiresAt = 0;
                        if (notOnOrAfter != null) {
                            expiresAt = notOnOrAfter.getTime();
                        } else {
                            expiresAt = currentTime + protocol.getStateTimeToLive();
                        }
                           
                        String webAppDomain = protocol.getWebAppDomain();
                        String token = DOM2Writer.nodeToString(wfRes.getToken());
                        List<String> roles = wfRes.getRoles();
                        if (roles == null || roles.size() == 0) {
                            roles = Collections.singletonList("Authenticated");
                        }
                        
                        ResponseState responseState = 
                            new ResponseState(token, // TODO
                                              params.getFirst("RelayState"), 
                                              null, // TODO
                                              webAppDomain,
                                              currentTime, 
                                              expiresAt);
                        responseState.setClaims(wfRes.getClaims());
                        responseState.setRoles(roles);
                        responseState.setIssuer(wfRes.getIssuer());
                        responseState.setSubject(wfRes.getUsername());
                        protocol.getStateManager().setResponseState(securityContextKey, responseState);
                           
                        long stateTimeToLive = protocol.getStateTimeToLive();
                        String contextCookie = createCookie(SECURITY_CONTEXT_TOKEN,
                                                            securityContextKey,
                                                            null, // TODO
                                                            webAppDomain,
                                                            stateTimeToLive);
                        
                        // Redirect with cookie set
                        ResponseBuilder response = 
                            Response.seeOther(new UriInfoImpl(m).getAbsolutePath());
                        response.header("Set-Cookie", contextCookie);

                        context.abortWith(response.build());
                    }
                    
                } else {
                    LOG.error("SignIn parameter is incorrect or not supported");
                    throw ExceptionUtils.toBadRequestException(null, null);
                }
            } catch (Exception ex) {
                LOG.debug(ex.getMessage(), ex);
                throw ExceptionUtils.toInternalServerErrorException(ex, null);
            }
        }
    }
    
    private boolean isSignInRequired(ContainerRequestContext context, FedizContext fedConfig) {
        
        MultivaluedMap<String, String> params = context.getUriInfo().getQueryParameters();
        if (fedConfig.getProtocol() instanceof FederationProtocol
            && params.getFirst(FederationConstants.PARAM_ACTION) == null) {
            return true;
        } else if (fedConfig.getProtocol() instanceof SAMLProtocol
            && params.getFirst(SAMLSSOConstants.RELAY_STATE) == null) {
            return true;
        }
        
        return false;
    }
    
    private boolean isSignInRequest(ContainerRequestContext context, FedizContext fedConfig) {
        
        MultivaluedMap<String, String> params = context.getUriInfo().getQueryParameters();
        if (fedConfig.getProtocol() instanceof FederationProtocol
            && FederationConstants.ACTION_SIGNIN.equals(
                params.getFirst(FederationConstants.PARAM_ACTION))) {
            return true;
        } else if (fedConfig.getProtocol() instanceof SAMLProtocol
            && params.getFirst(SAMLSSOConstants.RELAY_STATE) != null) {
            return true;
        }
        
        return false;
    }
    
    private String getResponseToken(ContainerRequestContext context, FedizContext fedConfig) {
        
        MultivaluedMap<String, String> params = context.getUriInfo().getQueryParameters();
        if (fedConfig.getProtocol() instanceof FederationProtocol) {
            return params.getFirst(FederationConstants.PARAM_RESULT);
        } else if (fedConfig.getProtocol() instanceof SAMLProtocol) {
            return params.getFirst(SAMLSSOConstants.SAML_RESPONSE);
        }
        
        return null;
    }
    
    private void validateAudienceRestrictions(
        FedizResponse wfRes, 
        List<String> audienceURIs,
        HttpServletRequest request
    ) {
        // Validate the AudienceRestriction in Security Token (e.g. SAML) 
        // against the configured list of audienceURIs
        if (wfRes.getAudience() != null) {
            boolean validAudience = false;
            for (String a : audienceURIs) {
                if (wfRes.getAudience().startsWith(a)) {
                    validAudience = true;
                    break;
                }
            }
            
            if (!validAudience) {
                LOG.warn("Token AudienceRestriction [" + wfRes.getAudience()
                         + "] doesn't match with specified list of URIs.");
                throw ExceptionUtils.toForbiddenException(null, null);
            }
            
            if (LOG.isDebugEnabled() && request.getRequestURL().indexOf(wfRes.getAudience()) == -1) {
                LOG.debug("Token AudienceRestriction doesn't match with request URL ["
                        + wfRes.getAudience() + "]  ["
                        + request.getRequestURL() + "]");
            }
        }
    }
}
