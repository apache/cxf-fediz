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
package org.apache.cxf.fediz.was.tai;

import java.io.File;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.ibm.websphere.security.CustomRegistryException;
import com.ibm.websphere.security.EntryNotFoundException;
import com.ibm.websphere.security.UserRegistry;
import com.ibm.websphere.security.WSSecurityException;
import com.ibm.websphere.security.WebTrustAssociationException;
import com.ibm.websphere.security.WebTrustAssociationFailedException;
import com.ibm.websphere.security.auth.WSSubject;
import com.ibm.wsspi.security.tai.TAIResult;
import com.ibm.wsspi.security.tai.TrustAssociationInterceptor;
import com.ibm.wsspi.security.token.AttributeNameConstants;

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.RequestState;
import org.apache.cxf.fediz.core.config.FedizConfigurator;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.handler.LogoutHandler;
import org.apache.cxf.fediz.core.handler.RequestHandler;
import org.apache.cxf.fediz.core.handler.SigninHandler;
import org.apache.cxf.fediz.core.metadata.MetadataDocumentHandler;
import org.apache.cxf.fediz.core.processor.FederationProcessorImpl;
import org.apache.cxf.fediz.core.processor.FedizProcessor;
import org.apache.cxf.fediz.core.processor.FedizResponse;
import org.apache.cxf.fediz.core.processor.RedirectionResponse;
import org.apache.cxf.fediz.was.Constants;
import org.apache.cxf.fediz.was.mapper.DefaultRoleToGroupMapper;
import org.apache.cxf.fediz.was.mapper.RoleToGroupMapper;
import org.apache.cxf.fediz.was.tai.exception.TAIConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A Trust Authentication Interceptor (TAI) that trusts a Sign-In-Response provided from a configured IP/STS
 * and instantiates the corresponding WAS Subject
 */
public class FedizInterceptor implements TrustAssociationInterceptor {
    private static final Logger LOG = LoggerFactory.getLogger(FedizInterceptor.class);

    private String configFile;
    private FedizConfigurator configurator;
    private RoleToGroupMapper mapper;

    /**
     * @see org.apache.cxf.fediz.was.Constants#PROPERTY_KEY_DIRECT_GROUP_MAPPING
     */
    private boolean directGrouMapping;

    public String getConfigFile() {
        return configFile;
    }

    public void setConfigFile(String configFile) {
        this.configFile = configFile;
    }

    /*
     * (non-Javadoc)
     * @see com.ibm.wsspi.security.tai.TrustAssociationInterceptor#cleanup()
     */
    @Override
    public void cleanup() {
        configurator = null;
        mapper = null;
    }

    /*
     * (non-Javadoc)
     * @see com.ibm.wsspi.security.tai.TrustAssociationInterceptor#getType()
     */
    @Override
    public String getType() {
        return this.getClass().getName();
    }

    /*
     * (non-Javadoc)
     * @see com.ibm.wsspi.security.tai.TrustAssociationInterceptor#getVersion()
     */
    @Override
    public String getVersion() {
        return Constants.VERSION;
    }

    /**
     * Registers a WebApplication using its contextPath as a key. This method must be called by the associated
     * security ServletFilter instance of a secured application at initialization time
     * 
     * @deprecated Not used/needed any longer since version 1.2.0
     * @param contextPath
     */
    @Deprecated
    public static void registerContext(String contextPath) {
    }

    /**
     * Deregister a WebApplication using its contextPath as a key. This method must be called by the
     * associated security ServletFilter instance of a secured application in the #destroy() method
     * 
     * @deprecated Not used/needed any longer since version 1.2.0
     * @param contextPath
     */
    @Deprecated
    public static void deRegisterContext(String contextPath) {
    }

    /*
     * (non-Javadoc)
     * @see com.ibm.wsspi.security.tai.TrustAssociationInterceptor#initialize(java.util.Properties)
     */
    @Override
    public int initialize(Properties props) throws WebTrustAssociationFailedException {
        if (props != null) {
            try {
                @SuppressWarnings("deprecation")
                String roleGroupMapper = props.containsKey(Constants.PROPERTY_KEY_ROLE_MAPPER)
                    ? props.getProperty(Constants.PROPERTY_KEY_ROLE_MAPPER)
                    : props.getProperty(Constants.ROLE_GROUP_MAPPER);
                if (roleGroupMapper != null && !roleGroupMapper.isEmpty()) {
                    try {
                        mapper = (RoleToGroupMapper)Class.forName(roleGroupMapper).newInstance();
                        LOG.debug("Using the {} mapper class", roleGroupMapper);
                        mapper.initialize(props);
                    } catch (Exception e) {
                        throw new TAIConfigurationException("Invalid TAI configuration for idpRoleToGroupMapper: "
                                                            + e.getClass().getName() + " " + e.getMessage());
                    }
                } else {
                    mapper = new DefaultRoleToGroupMapper();
                    LOG.debug("Using the DefaultRoleToGroupMapper mapper class");
                }

                @SuppressWarnings("deprecation")
                String configFileLocation = props.containsKey(Constants.PROPERTY_KEY_CONFIG_LOCATION)
                    ? props.getProperty(Constants.PROPERTY_KEY_CONFIG_LOCATION)
                    : props.getProperty(Constants.CONFIGURATION_FILE_PARAMETER);
                if (configFileLocation != null) {
                    LOG.debug("Configuration file location set to {}", configFileLocation);
                    File f = new File(configFileLocation);

                    configurator = new FedizConfigurator();
                    configurator.loadConfig(f);

                    LOG.debug("Federation config loaded from path: {}", configFileLocation);
                } else {
                    throw new WebTrustAssociationFailedException("Missing required initialization parameter "
                                                                 + Constants.PROPERTY_KEY_CONFIG_LOCATION);
                }

                directGrouMapping = Boolean.valueOf(props.getProperty(Constants.PROPERTY_KEY_DIRECT_GROUP_MAPPING));
            } catch (Throwable t) {
                LOG.warn("Failed initializing TAI", t);
                return 1;
            }
        }
        return 0;
    }

    private FedizContext getFederationContext(HttpServletRequest req) {
        String contextPath = req.getContextPath();
        if (contextPath == null || contextPath.isEmpty()) {
            contextPath = "/";
        }
        return configurator.getFedizContext(contextPath);

    }

    /*
     * (non-Javadoc)
     * @see com.ibm.wsspi.security.tai.TrustAssociationInterceptor#isTargetInterceptor(javax.servlet.http.
     * HttpServletRequest)
     */
    @Override
    public boolean isTargetInterceptor(HttpServletRequest req) throws WebTrustAssociationException {
        LOG.debug("Request URI: {}", req.getRequestURI());
        FedizContext context = getFederationContext(req);

        if (context != null) {
            return true;
        } else {
            LOG.warn("No Federation Context configured for context-path {}", req.getContextPath());
        }
        return false;
    }

    /*
     * (non-Javadoc)
     * @see
     * com.ibm.wsspi.security.tai.TrustAssociationInterceptor#negotiateValidateandEstablishTrust(javax.servlet
     * .http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    public TAIResult negotiateValidateandEstablishTrust(HttpServletRequest req, HttpServletResponse resp)
        throws WebTrustAssociationFailedException {

        LOG.debug("Request URI: {}", req.getRequestURI());
        FedizContext fedCtx = getFederationContext(req);

        if (fedCtx == null) {
            LOG.warn("No Federation Context configured for context-path {}", req.getContextPath());
            return TAIResult.create(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }

        try {

            // Handle Metadata Document requests
            RequestHandler mddHandler = new MetadataDocumentHandler(fedCtx);
            if (mddHandler.canHandleRequest(req)) {
                boolean success = mddHandler.handleRequest(req, resp);
                return TAIResult.create(success
                    ? HttpServletResponse.SC_OK
                    : HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }

            // Handle Logout requests
            LogoutHandler logoutHandler = new LogoutHandler(fedCtx);
            if (logoutHandler.canHandleRequest(req)) {
                boolean success = logoutHandler.handleRequest(req, resp);
                return TAIResult.create(success
                    ? HttpServletResponse.SC_OK
                    : HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }

            // Handle Signin requests
            SigninHandler signinHandler = new SigninHandler(fedCtx) {
                @Override
                public void resumeRequest(HttpServletRequest request, HttpServletResponse response,
                    FedizResponse federationResponse) {
                    String wctx = request.getParameter(FederationConstants.PARAM_CONTEXT);
                    HttpSession session = request.getSession(true);
                    session.setAttribute(Constants.SECURITY_TOKEN_SESSION_ATTRIBUTE_KEY, federationResponse);
                    RequestState requestState = (RequestState)session.getAttribute(wctx);
                    if (requestState != null && requestState.getTargetAddress() != null) {
                        LOG.info("Redirecting request to {}", requestState.getTargetAddress());
                        try {
                            response.sendRedirect(requestState.getTargetAddress());
                        } catch (IOException e) {
                            LOG.error("Cannot resume with original request.", e);
                        }
                        session.removeAttribute(wctx);
                    }
                }
            };
            if (signinHandler.canHandleRequest(req)) {
                signinHandler.handleRequest(req, resp);
                return TAIResult.create(HttpServletResponse.SC_FOUND);
            }

            // Check if user was authenticated previously and token is still valid
            String user = req.getRemoteUser();
            String principal = WSSubject.getCallerPrincipal();
            Subject subject = null;
            try {
                subject = WSSubject.getCallerSubject();
            } catch (WSSecurityException e) {
                LOG.error("Could not read subject");
            }
            LOG.info("Remote User: {}, Principal: {}, Subject {}", user, principal, subject);
            if (principal != null && subject != null) {
                // return TAIResult.create(HttpServletResponse.SC_OK, principal, subject);
            } else {
                TAIResult taiResult = checkUserAuthentication(req);
                if (taiResult != null) {
                    return taiResult;
                }
            }

            LOG.info("No Subject found in existing session. Redirecting to IDP");
            redirectToIdp(req, resp, fedCtx);
            return TAIResult.create(HttpServletResponse.SC_FOUND);

        } catch (Exception e) {
            LOG.error("Exception occured validating request", e);
            throw new WebTrustAssociationFailedException(e.getMessage());
        }
    }

    private TAIResult checkUserAuthentication(HttpServletRequest req) throws Exception {
        TAIResult result = null;
        HttpSession session = req.getSession(false);
        if (session != null) {
            LOG.debug("Session ID is {}", session.getId());
            FedizResponse federationResponse = (FedizResponse)session
                .getAttribute(Constants.SECURITY_TOKEN_SESSION_ATTRIBUTE_KEY);
            if (federationResponse != null) {
                LOG.info("Security Token found in session: {}", federationResponse.getUsername());

                // check that the target WebApp is properly configured for Token TTL enforcement
                if (checkSecurityToken(federationResponse)) {
                    // proceed creating the JAAS Subject
                    LOG.info("Security Filter properly configured - forwarding subject");
                    List<String> groupsIds = groupIdsFromTokenRoles(federationResponse);
                    Subject subject = createSubject(federationResponse, groupsIds, session.getId());

                    result = TAIResult.create(HttpServletResponse.SC_OK, federationResponse.getUsername(), subject);
                }
                // leave the Session untouched
                // session.removeAttribute(Constants.SECURITY_TOKEN_SESSION_ATTRIBUTE_KEY);
            }
        }
        return result;
    }

    protected void redirectToIdp(HttpServletRequest request, HttpServletResponse response, FedizContext fedCtx)
        throws IOException, WebTrustAssociationFailedException {
        FedizProcessor processor = new FederationProcessorImpl();

        try {
            RedirectionResponse redirectionResponse = processor.createSignInRequest(request, fedCtx);
            String redirectURL = redirectionResponse.getRedirectionURL();
            if (redirectURL != null) {
                Map<String, String> headers = redirectionResponse.getHeaders();
                if (!headers.isEmpty()) {
                    for (String headerName : headers.keySet()) {
                        response.addHeader(headerName, headers.get(headerName));
                    }
                }
                // Save request in our session before redirect to IDP
                RequestState requestState = redirectionResponse.getRequestState();
                if (requestState != null) {
                    HttpSession session = request.getSession(true);
                    session.setAttribute(requestState.getState(), requestState);
                }
                response.sendRedirect(redirectURL);
            } else {
                LOG.error("RedirectUrl is null. Failed to create SignInRequest.");
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to create SignInRequest.");
            }
        } catch (ProcessingException ex) {
            LOG.error("Failed to create SignInRequest", ex);
            throw new WebTrustAssociationFailedException(ex.getMessage());
        }
    }

    protected FedizResponse getCachedFederationResponse(Subject subject) {
        Iterator<?> i = subject.getPublicCredentials().iterator();
        while (i.hasNext()) {
            Object o = i.next();
            if (o instanceof Hashtable) {
                Map<?, ?> table = (Hashtable<?, ?>)o;
                return (FedizResponse)table.get(Constants.SUBJECT_TOKEN_KEY);
            }
        }
        return null;
    }

    private boolean checkSecurityToken(FedizResponse response) {
        if (response == null) {
            return false;
        }
        long currentTime = System.currentTimeMillis();
        return response.getTokenExpires().getTime() > currentTime;
    }

    private List<String> groupIdsFromTokenRoles(FedizResponse federationResponse) throws Exception {

        List<String> localGroups = mapper.groupsFromRoles(federationResponse.getRoles());
        List<String> groupIds = new ArrayList<String>(localGroups.size());

        if (directGrouMapping) {
            LOG.debug("Direct Group Mapping was set in interceptor. Thus UserRegistry will not be invoked to get "
                      + "GrouUID");
            groupIds.addAll(localGroups);
        } else {
            InitialContext ctx = new InitialContext();
            try {
                UserRegistry reg = (UserRegistry)ctx.lookup(Constants.USER_REGISTRY_JNDI_NAME);

                if (localGroups != null) {
                    LOG.debug("Converting {} group names to uids", localGroups.size());
                    for (String localGroup : localGroups) {
                        try {
                            String guid = convertGroupNameToUniqueId(reg, localGroup);
                            LOG.debug("Group '{}' maps to guid: {}", localGroup, guid);
                            groupIds.add(guid);
                        } catch (EntryNotFoundException e) {
                            LOG.warn("Group entry '{}' could not be found in UserRegistry for user '{}'", localGroup,
                                     federationResponse.getUsername());
                        }
                    }
                }
            } catch (NamingException ex) {
                LOG.error("User Registry could not be loaded via JNDI context.");
                LOG.warn("Since Group mapping failed no groups will be set for user '{}'", federationResponse
                    .getUsername());
                LOG.info("To switch to direct GroupUID Mapping without UserRegistry being involved set "
                         + "fedizDirectGroupMapping=\"true\"  in TAI Interceptor properties.");
            } finally {
                ctx.close();
            }
        }
        LOG.debug("Group list: {}", groupIds);
        return groupIds;
    }

    /**
     * Creates the JAAS Subject so that WAS Runtime will not check the local registry
     */
    private Subject createSubject(FedizResponse federationResponse, List<String> groups, String cacheKey) {
        String uniqueId = "user:defaultWIMFileBasedRealm/cn=" + federationResponse.getUsername()
                          + ",o=defaultWIMFileBasedRealm";
        String completeCacheKey = uniqueId + ':' + cacheKey;

        // creating the JAAS Subject so that WAS won't do a lookup in the registry
        Subject subject = new Subject();

        Map<String, Object> map = new Hashtable<String, Object>();
        map.put(AttributeNameConstants.WSCREDENTIAL_UNIQUEID, uniqueId);
        map.put(AttributeNameConstants.WSCREDENTIAL_SECURITYNAME, federationResponse.getUsername());
        map.put(AttributeNameConstants.WSCREDENTIAL_GROUPS, groups);
        map.put(AttributeNameConstants.WSCREDENTIAL_CACHE_KEY, completeCacheKey);
        // caching the WS-Federation security token for further reuse by the application
        map.put(Constants.SUBJECT_TOKEN_KEY, federationResponse);

        subject.getPublicCredentials().add(map);

        LOG.debug("Subject credentials: {}", map.toString());
        return subject;
    }

    /**
     * Convenience method for converting a list of group names to their unique group IDs
     * 
     * @param reg
     * @param group
     * @return
     * @throws EntryNotFoundException
     * @throws CustomRegistryException
     * @throws RemoteException
     */
    private String convertGroupNameToUniqueId(UserRegistry reg, String group) throws EntryNotFoundException,
        CustomRegistryException, RemoteException {
        return reg.getUniqueGroupId(group);
    }
}
