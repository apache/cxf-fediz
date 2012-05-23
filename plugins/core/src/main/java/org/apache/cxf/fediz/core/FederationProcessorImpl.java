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

package org.apache.cxf.fediz.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLEncoder;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import org.apache.cxf.fediz.core.config.FederationContext;
import org.apache.cxf.fediz.core.config.FederationProtocol;
import org.apache.cxf.fediz.core.saml.SAMLTokenValidator;
import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.util.XmlSchemaDateFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class FederationProcessorImpl implements FederationProcessor {

    private static final Logger LOG = LoggerFactory.getLogger(FederationProcessorImpl.class);

    private TokenReplayCache<String> replayCache;

    /**
     * Default constructor
     */
    public FederationProcessorImpl() {
        super();
        replayCache = new EHCacheTokenReplayCache();
    }

    /**
     * 
     * @param replayCache
     *            plugable token cache allowing to provide a replicated cache to
     *            be used in clustered scenarios
     */
    public FederationProcessorImpl(TokenReplayCache<String> replayCache) {
        super();
        this.replayCache = replayCache;
    }

    @Override
    public FederationResponse processRequest(FederationRequest request,
                                             FederationContext config) {
        FederationResponse response = null;
        if (request.getWa().equals(FederationConstants.ACTION_SIGNIN)) {
            response = this.processSignInRequest(request, config);
        }
        return response;
    }

    protected FederationResponse processSignInRequest(
            FederationRequest request, FederationContext config) {

        byte[] wresult = request.getWresult().getBytes();

        Document doc = null;
        Element el = null;
        try {
            doc = DOMUtils.readXml(new ByteArrayInputStream(wresult));
            el = doc.getDocumentElement();

        } catch (SAXException e) {
            e.printStackTrace();
            return null;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }

        if ("RequestSecurityTokenResponseCollection".equals(el.getLocalName())) {
            el = DOMUtils.getFirstElement(el);
        }
        if (!"RequestSecurityTokenResponse".equals(el.getLocalName())) {
            throw new RuntimeException("Unexpected element "
                    + el.getLocalName());
        }
        el = DOMUtils.getFirstElement(el);
        Element rst = null;
        Element lifetimeElem = null;
        String tt = null;

        while (el != null) {
            String ln = el.getLocalName();
            if (FederationConstants.WS_TRUST_13_NS.equals(el.getNamespaceURI()) 
                || FederationConstants.WS_TRUST_2005_02_NS.equals(el.getNamespaceURI())) {
                if ("Lifetime".equals(ln)) {
                    lifetimeElem = el;
                } else if ("RequestedSecurityToken".equals(ln)) {
                    rst = DOMUtils.getFirstElement(el);
                } else if ("TokenType".equals(ln)) {
                    tt = DOMUtils.getContent(el);
                }
            }
            el = DOMUtils.getNextElement(el);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("RST: " + rst.toString());
            LOG.debug("Lifetime: "
                    + ((lifetimeElem != null) ? lifetimeElem.toString()
                            : "null"));
            LOG.debug("Tokentype: " + ((tt != null) ? tt.toString() : "null"));
        }
        if (rst == null) {
            LOG.info("RST is null");
            throw new RuntimeException("RST is null");
        }
        LifeTime lifeTime = null;
        if (lifetimeElem != null) {
            lifeTime = processLifeTime(lifetimeElem);
        }

        if (config.isDetectExpiredTokens() && lifeTime != null) {
            Date currentDate = new Date();
            if (currentDate.after(lifeTime.getExpires())) {
                LOG.warn("Token already expired");
            }

            if (currentDate.before(lifeTime.getCreated())) {
                LOG.warn("Token not yet valid");
                // [TODO] Add Check clocksqew
            }
        }

        // [TODO] Exception: TokenExpiredException, TokenInvalidException,
        // TokenCachedException

        // [TODO] Flexible tokenvalidator selection, based on class list
        SAMLTokenValidator validator = new SAMLTokenValidator();
        TokenValidatorResponse response = validator.validateAndProcessToken(
                rst, config);

        // Check whether token already used for signin
        if (response.getUniqueTokenId() != null
                && config.isDetectReplayedTokens()) {
            // Check whether token has already been processed once, prevent
            // replay attack

            if (replayCache.getId(response.getUniqueTokenId()) == null) {
                // not cached
                replayCache.putId(response.getUniqueTokenId());
            } else {
                LOG.error("Replay attack with token id: "
                        + response.getUniqueTokenId());
                throw new RuntimeException("Replay attack with token id: "
                        + response.getUniqueTokenId());
            }
        }

        // [TODO] Token, WeakReference, SoftReference???
        FederationResponse fedResponse = new FederationResponse(
                response.getUsername(), response.getIssuer(),
                response.getRoles(), response.getClaims(),
                response.getAudience(),
                (lifeTime != null) ? lifeTime.getCreated() : null,
                        (lifeTime != null) ? lifeTime.getExpires() : null, rst,
                                response.getUniqueTokenId());

        return fedResponse;
    }

    private LifeTime processLifeTime(Element lifetimeElem) {
        // [TODO] Get rid of WSS4J dependency
        try {
            Element createdElem = DOMUtils.getFirstChildWithName(lifetimeElem,
                    WSConstants.WSU_NS, WSConstants.CREATED_LN);
            DateFormat zulu = new XmlSchemaDateFormat();

            Date created = zulu.parse(DOMUtils.getContent(createdElem));

            Element expiresElem = DOMUtils.getFirstChildWithName(lifetimeElem,
                    WSConstants.WSU_NS, WSConstants.EXPIRES_LN);
            Date expires = zulu.parse(DOMUtils.getContent(expiresElem));

            return new LifeTime(created, expires);

        } catch (ParseException e) {
            e.printStackTrace();
        }
        return null;
    }

    public class LifeTime {

        private Date created;
        private Date expires;

        public LifeTime(Date created, Date expires) {
            this.created = created;
            this.expires = expires;
        }

        public Date getCreated() {
            return created;
        }

        public Date getExpires() {
            return expires;
        }

    }

    @Override
    public String createSignInRequest(HttpServletRequest request, FederationContext config) {

        String redirectURL = null;
        // if (this.getIssuerCallbackHandler() != null) {
        // org.apache.cxf.fediz.core.spi.IDPCallback callback = new org.apache.cxf.fediz.core.spi.IDPCallback(
        // request);
        // try {
        // this.getIssuerCallbackHandler().handle(
        // new Callback[] { callback });
        // redirectURL = callback.getIssuerUrl().toString();
        // String trustedIssuer = callback.getTrustedIssuer();
        // if (trustedIssuer != null && trustedIssuer.length() > 0) {
        // request.getSessionInternal().setNote(TRUSTED_ISSUER,
        // trustedIssuer);
        // }
        // } catch (Exception ex) {
        // log.error("Failed to handle callback: " + ex.getMessage());
        // }
        // }
        try {
            String issuerURL = ((FederationProtocol)config.getProtocol()).getIssuer();
            if (issuerURL != null && issuerURL.length() > 0) {
                redirectURL = issuerURL;
            }
            LOG.info("Issuer url: " + redirectURL);

            StringBuilder sb = new StringBuilder();

            sb.append(FederationConstants.PARAM_ACTION).append('=').append(FederationConstants.ACTION_SIGNIN);

            sb.append('&').append(FederationConstants.PARAM_REPLY).append('=');
            sb.append(URLEncoder.encode(request.getRequestURL().toString(), "UTF-8"));

            String realm = null;
            FederationProtocol fp = null;
            if (config.getProtocol() instanceof FederationProtocol) {
                fp = (FederationProtocol)config.getProtocol();
            } else {
                LOG.error("Unsupported protocol");
                throw new IllegalStateException("Unsupported protocol");
            }
            if (fp.getRealm() != null) {
                realm = fp.getRealm();
            } else {
                String contextPath = request.getContextPath();
                String requestUrl = request.getRequestURL().toString();
                String requestPath = new URL(requestUrl).getPath();
                // Cut request path of request url and add context path if not ROOT
                if (requestPath != null && requestPath.length() > 0) {
                    int lastIndex = requestUrl.lastIndexOf(requestPath);
                    realm = requestUrl.substring(0, lastIndex);
                } else {
                    realm = requestUrl;
                }
                if (contextPath != null && contextPath.length() > 0) {
                    // contextPath contains starting slash
                    realm = realm + contextPath + "/";
                } else {
                    realm = realm + "/";
                }
            }
            LOG.debug("wtrealm=" + realm);

            StringBuffer realmSb = new StringBuffer(request.getScheme());
            realmSb.append("://").append(request.getServerName()).append(":").append(request.getServerPort())
                .append(request.getContextPath());
            sb.append('&').append(FederationConstants.PARAM_TREALM).append('=')
                .append(URLEncoder.encode(realm, "UTF-8"));
            redirectURL = redirectURL + "?" + sb.toString();
        } catch (Exception ex) {
            LOG.error("Failed to create SignInRequest", ex);
            return null;
        }
        // [TODO] Current time, wct

        // if (false) {
        // sb.append("&");
        // sb.append("wfresh=jjjj");
        // }
        // if (false) {
        // sb.append("&");
        // sb.append("wauth=jjjj");
        // }
        // if (false) {
        // sb.append("&");wct
        // sb.append("wreq=jjjj");
        // }
        // if (false) {
        // sb.append("&");
        // sb.append("wct=").append("jjjj");
        // }
        return redirectURL;
    }


}
