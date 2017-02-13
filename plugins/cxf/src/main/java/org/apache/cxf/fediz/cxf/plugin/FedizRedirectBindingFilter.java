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

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.UUID;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.w3c.dom.Document;

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.RequestState;
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
import org.apache.cxf.fediz.core.util.CookieUtils;
import org.apache.cxf.fediz.cxf.plugin.state.ResponseState;
import org.apache.cxf.helpers.IOUtils;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.jaxrs.impl.HttpHeadersImpl;
import org.apache.cxf.jaxrs.impl.UriInfoImpl;
import org.apache.cxf.jaxrs.utils.ExceptionUtils;
import org.apache.cxf.jaxrs.utils.JAXRSUtils;
import org.apache.cxf.message.Message;
import org.apache.wss4j.common.util.DOM2Writer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FedizRedirectBindingFilter extends AbstractServiceProviderFilter
    implements ContainerResponseFilter {

    private static final Logger LOG = LoggerFactory.getLogger(FedizRedirectBindingFilter.class);

    @Context
    private MessageContext messageContext;

    private boolean redirectOnInitialSignIn;

    public void filter(ContainerRequestContext context) {
        Message m = JAXRSUtils.getCurrentMessage();
        FedizContext fedConfig = getFedizContext(m);

        // See if it is a Metadata request
        if (isMetadataRequest(context, fedConfig)) {
            return;
        }

        String httpMethod = context.getMethod();
        MultivaluedMap<String, String> params = null;

        try {
            if (HttpMethod.GET.equals(httpMethod)) {
                params = context.getUriInfo().getQueryParameters();
            } else if (HttpMethod.POST.equals(httpMethod)) {
                String strForm = IOUtils.toString(context.getEntityStream());
                params = JAXRSUtils.getStructuredParams(strForm, "&", true, false);
            }
        } catch (Exception ex) {
            LOG.debug(ex.getMessage(), ex);
            throw ExceptionUtils.toInternalServerErrorException(ex, null);
        }

        // See if it is a Logout request first
        if (isLogoutRequest(context, fedConfig, m, params) || isSignoutCleanupRequest(fedConfig, m, params)) {
            return;
        } else if (checkSecurityContext(fedConfig, m, params)) {
            return;
        } else if (isSignInRequired(fedConfig, params)) {
            processSignInRequired(context, fedConfig);
        } else if (isSignInRequest(fedConfig, params)) {
            processSignInRequest(context, fedConfig, m, params);
        } else {
            LOG.error("SignIn parameter is incorrect or not supported");
            throw ExceptionUtils.toBadRequestException(null, null);
        }
    }

    private void processSignInRequest(ContainerRequestContext context, FedizContext fedConfig,
                                      Message m, MultivaluedMap<String, String> params) {
        String responseToken = getResponseToken(fedConfig, params);
        String state = getState(fedConfig, params);

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

            FedizResponse wfRes =
                validateSignInRequest(fedConfig, params, responseToken, state);

            // Validate AudienceRestriction
            List<String> audienceURIs = fedConfig.getAudienceUris();
            HttpServletRequest request = messageContext.getHttpServletRequest();
            validateAudienceRestrictions(wfRes, audienceURIs, request);

            // Set the security context
            String securityContextKey = UUID.randomUUID().toString();

            long currentTime = System.currentTimeMillis();
            Date notOnOrAfter = wfRes.getTokenExpires();
            long expiresAt = 0;
            if (notOnOrAfter != null) {
                expiresAt = notOnOrAfter.getTime();
            } else {
                expiresAt = currentTime + getStateTimeToLive();
            }

            String webAppDomain = getWebAppDomain();
            String token = DOM2Writer.nodeToString(wfRes.getToken());
            // Add "Authenticated" role
            List<String> roles = wfRes.getRoles();
            if (roles == null || roles.size() == 0) {
                roles = Collections.singletonList("Authenticated");
            } else if (fedConfig.isAddAuthenticatedRole()) {
                roles = new ArrayList<>(roles);
                roles.add("Authenticated");
            }

            String webAppContext = getWebAppContext(m);

            ResponseState responseState =
                new ResponseState(token,
                                  state,
                                  webAppContext,
                                  webAppDomain,
                                  currentTime,
                                  expiresAt);
            responseState.setClaims(wfRes.getClaims());
            responseState.setRoles(roles);
            responseState.setIssuer(wfRes.getIssuer());
            responseState.setSubject(wfRes.getUsername());
            getStateManager().setResponseState(securityContextKey, responseState);

            long stateTimeToLive = getStateTimeToLive();
            String contextCookie = CookieUtils.createCookie(SECURITY_CONTEXT_TOKEN,
                                                            securityContextKey,
                                                            webAppContext,
                                                            webAppDomain,
                                                            stateTimeToLive);

            // Redirect with cookie set
            if (isRedirectOnInitialSignIn()) {
                ResponseBuilder response =
                    Response.seeOther(new UriInfoImpl(m).getAbsolutePath());
                response.header(HttpHeaders.SET_COOKIE, contextCookie);

                context.abortWith(response.build());
            } else {
                try {
                    setSecurityContext(responseState, m, wfRes.getToken());
                    context.setProperty(SECURITY_CONTEXT_TOKEN, contextCookie);
                } catch (Exception ex) {
                    reportError("INVALID_RESPONSE_STATE");
                }
            }
        }

    }

    private void processSignInRequired(ContainerRequestContext context, FedizContext fedConfig) {
     // Unauthenticated -> redirect
        FedizProcessor processor =
            FedizProcessorFactory.newFedizProcessor(fedConfig.getProtocol());

        HttpServletRequest request = messageContext.getHttpServletRequest();
        try {
            RedirectionResponse redirectionResponse =
                processor.createSignInRequest(request, fedConfig);
            String redirectURL = redirectionResponse.getRedirectionURL();
            if (redirectURL != null) {
                ResponseBuilder response = Response.seeOther(new URI(redirectURL));
                Map<String, String> headers = redirectionResponse.getHeaders();
                if (!headers.isEmpty()) {
                    for (Entry<String, String> entry : headers.entrySet()) {
                        response.header(entry.getKey(), entry.getValue());
                    }
                }

                // Save the RequestState
                RequestState requestState = redirectionResponse.getRequestState();
                if (requestState != null && requestState.getState() != null) {
                    getStateManager().setRequestState(requestState.getState(), requestState);

                    String contextCookie =
                        CookieUtils.createCookie(SECURITY_CONTEXT_STATE,
                                                 requestState.getState(),
                                                 request.getRequestURI(),
                                                 getWebAppDomain(),
                                                 getStateTimeToLive());
                    response.header(HttpHeaders.SET_COOKIE, contextCookie);
                }

                context.abortWith(response.build());
            } else {
                LOG.warn("Failed to create SignInRequest.");
                throw ExceptionUtils.toInternalServerErrorException(null, null);
            }
        } catch (Exception ex) {
            LOG.debug(ex.getMessage(), ex);
            throw ExceptionUtils.toInternalServerErrorException(ex, null);
        }

    }

    private boolean isMetadataRequest(ContainerRequestContext context, FedizContext fedConfig) {
        String requestPath = context.getUriInfo().getPath();
        // See if it is a Metadata request
        if (requestPath.indexOf(FederationConstants.METADATA_PATH_URI) != -1
            || requestPath.indexOf(getMetadataURI(fedConfig)) != -1) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Metadata document requested");
            }

            FedizProcessor wfProc =
                FedizProcessorFactory.newFedizProcessor(fedConfig.getProtocol());
            try {
                HttpServletRequest request = messageContext.getHttpServletRequest();
                Document metadata = wfProc.getMetaData(request, fedConfig);
                String metadataStr = DOM2Writer.nodeToString(metadata);

                ResponseBuilder response = Response.ok(metadataStr, "text/xml");
                context.abortWith(response.build());
                return true;
            } catch (Exception ex) {
                LOG.error("Failed to get metadata document: " + ex.getMessage());
                throw ExceptionUtils.toInternalServerErrorException(ex, null);
            }
        }

        return false;
    }

    private boolean isLogoutRequest(ContainerRequestContext context, FedizContext fedConfig,
                                    Message message, MultivaluedMap<String, String> params) {

        boolean signout = false;
        String logoutUrl = fedConfig.getLogoutURL();
        if (params != null && fedConfig.getProtocol() instanceof FederationProtocol
            && FederationConstants.ACTION_SIGNOUT.equals(
                params.getFirst(FederationConstants.PARAM_ACTION))) {
            signout = true;
        } else if (logoutUrl != null && !logoutUrl.isEmpty()) {
            String requestPath = "/" + context.getUriInfo().getPath();
            if (requestPath.equals(logoutUrl) || requestPath.equals(logoutUrl + "/")) {
                signout = true;
            }
        }

        if (signout) {
            cleanupContext(message);

            try {
                FedizProcessor processor =
                    FedizProcessorFactory.newFedizProcessor(fedConfig.getProtocol());

                HttpServletRequest request = messageContext.getHttpServletRequest();
                RedirectionResponse redirectionResponse =
                    processor.createSignOutRequest(request, null, fedConfig); //TODO
                String redirectURL = redirectionResponse.getRedirectionURL();
                if (redirectURL != null) {
                    ResponseBuilder response = Response.seeOther(new URI(redirectURL));
                    Map<String, String> headers = redirectionResponse.getHeaders();
                    if (!headers.isEmpty()) {
                        for (Entry<String, String> entry : headers.entrySet()) {
                            response.header(entry.getKey(), entry.getValue());
                        }
                    }

                    context.abortWith(response.build());

                    return true;
                }
            } catch (Exception ex) {
                LOG.debug(ex.getMessage(), ex);
                throw ExceptionUtils.toInternalServerErrorException(ex, null);
            }
        }

        return false;
    }

    private void cleanupContext(Message message) {
        HttpHeaders headers = new HttpHeadersImpl(message);
        Map<String, Cookie> cookies = headers.getCookies();
        if (cookies.containsKey(SECURITY_CONTEXT_TOKEN)) {
            String contextKey = cookies.get(SECURITY_CONTEXT_TOKEN).getValue();
            getStateManager().removeResponseState(contextKey);
        }
        if (cookies.containsKey(SECURITY_CONTEXT_STATE)) {
            String contextKey = cookies.get(SECURITY_CONTEXT_STATE).getValue();
            getStateManager().removeRequestState(contextKey);
        }
    }

    private String getMetadataURI(FedizContext fedConfig) {
        if (fedConfig.getProtocol().getMetadataURI() != null) {
            return fedConfig.getProtocol().getMetadataURI();
        } else if (fedConfig.getProtocol() instanceof FederationProtocol) {
            return FederationConstants.METADATA_PATH_URI;
        } else if (fedConfig.getProtocol() instanceof SAMLProtocol) {
            return SAMLSSOConstants.FEDIZ_SAML_METADATA_PATH_URI;
        }

        return FederationConstants.METADATA_PATH_URI;
    }

    private boolean isSignInRequired(FedizContext fedConfig, MultivaluedMap<String, String> params) {
        if (params != null && fedConfig.getProtocol() instanceof FederationProtocol
            && params.getFirst(FederationConstants.PARAM_ACTION) == null) {
            return true;
        } else if (params != null && fedConfig.getProtocol() instanceof SAMLProtocol
            && params.getFirst(SAMLSSOConstants.RELAY_STATE) == null) {
            return true;
        }

        return false;
    }

    private boolean isSignInRequest(FedizContext fedConfig, MultivaluedMap<String, String> params) {
        if (params != null && fedConfig.getProtocol() instanceof FederationProtocol
            && FederationConstants.ACTION_SIGNIN.equals(
                params.getFirst(FederationConstants.PARAM_ACTION))) {
            return true;
        } else if (params != null && fedConfig.getProtocol() instanceof SAMLProtocol
            && params.getFirst(SAMLSSOConstants.RELAY_STATE) != null) {
            return true;
        }

        return false;
    }

    private boolean isSignoutCleanupRequest(FedizContext fedConfig, Message m, MultivaluedMap<String, String> params) {

        boolean signoutCleanup = false;
        if (params != null && fedConfig.getProtocol() instanceof FederationProtocol
            && FederationConstants.ACTION_SIGNOUT_CLEANUP.equals(
                params.getFirst(FederationConstants.PARAM_ACTION))) {
            signoutCleanup = true;
        } /* TODO else if (params != null && fedConfig.getProtocol() instanceof SAMLProtocol
            && params.getFirst(SAMLSSOConstants.RELAY_STATE) != null) {
            signoutCleanup = true;
        }*/

        if (signoutCleanup) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("SignOutCleanup request found");
                LOG.debug("SignOutCleanup action...");
            }
            cleanupContext(m);

            HttpServletResponse response = messageContext.getHttpServletResponse();
            try {
                final ServletOutputStream responseOutputStream = response.getOutputStream();
                InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream("logout.jpg");
                if (inputStream == null) {
                    LOG.warn("Could not write logout.jpg");
                    return true;
                }
                int read = 0;
                byte[] buf = new byte[1024];
                while ((read = inputStream.read(buf)) != -1) {
                    responseOutputStream.write(buf, 0, read);
                }
                inputStream.close();
                responseOutputStream.flush();
            } catch (Exception ex) {
                LOG.debug(ex.getMessage(), ex);
                throw ExceptionUtils.toInternalServerErrorException(ex, null);
            }

            return true;
        }

        return false;
    }

    private String getResponseToken(FedizContext fedConfig, MultivaluedMap<String, String> params) {
        if (params != null && fedConfig.getProtocol() instanceof FederationProtocol) {
            return params.getFirst(FederationConstants.PARAM_RESULT);
        } else if (params != null && fedConfig.getProtocol() instanceof SAMLProtocol) {
            return params.getFirst(SAMLSSOConstants.SAML_RESPONSE);
        }

        return null;
    }

    private FedizResponse validateSignInRequest(
        FedizContext fedConfig,
        MultivaluedMap<String, String> params,
        String responseToken,
        String state
    ) {
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(params.getFirst(FederationConstants.PARAM_ACTION));
        wfReq.setResponseToken(responseToken);

        if (state == null || state.getBytes().length <= 0) {
            LOG.error("Invalid RelayState/WCTX");
            throw ExceptionUtils.toBadRequestException(null, null);
        }

        wfReq.setState(state);
        wfReq.setRequestState(getStateManager().removeRequestState(state));

        if (wfReq.getRequestState() == null) {
            LOG.error("Missing Request State");
            throw ExceptionUtils.toBadRequestException(null, null);
        }

        if (CookieUtils.isStateExpired(wfReq.getRequestState().getCreatedAt(), false, 0,
                                       getStateTimeToLive())) {
            LOG.error("EXPIRED_REQUEST_STATE");
            throw ExceptionUtils.toBadRequestException(null, null);
        }

        HttpServletRequest request = messageContext.getHttpServletRequest();
        wfReq.setRequest(request);

        X509Certificate certs[] =
            (X509Certificate[])request.getAttribute("javax.servlet.request.X509Certificate");
        wfReq.setCerts(certs);

        FedizProcessor wfProc =
            FedizProcessorFactory.newFedizProcessor(fedConfig.getProtocol());
        try {
            return wfProc.processRequest(wfReq, fedConfig);
        } catch (ProcessingException ex) {
            LOG.error("Federation processing failed: " + ex.getMessage());
            throw ExceptionUtils.toNotAuthorizedException(ex, null);
        }
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

    public boolean isRedirectOnInitialSignIn() {
        return redirectOnInitialSignIn;
    }

    public void setRedirectOnInitialSignIn(boolean redirectOnInitialSignIn) {
        this.redirectOnInitialSignIn = redirectOnInitialSignIn;
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext)
            throws IOException {
        String tokenContext = (String)requestContext.getProperty(SECURITY_CONTEXT_TOKEN);
        if (tokenContext != null) {
            responseContext.getHeaders().add(HttpHeaders.SET_COOKIE, tokenContext);
        }

    }

}
