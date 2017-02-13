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

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Constants specific to WS-Federation
 */
public final class FederationConstants extends FedizConstants {

    public static final String WSFED_METHOD = "WSFED";

    /**
     * Constants defined in following spec:
     * http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html
     */

    /**
     * This REQUIRED parameter specifies the action to be performed. Note that this serves roughly the same
     * purpose as the WS-Addressing Action header for the WS-Trust SOAP RST messages.
     */
    public static final String PARAM_ACTION = "wa";

    public static final String ACTION_SIGNIN = "wsignin1.0";
    public static final String ACTION_SIGNOUT = "wsignout1.0";
    public static final String ACTION_SIGNOUT_CLEANUP = "wsignoutcleanup1.0";

    /**
     * This OPTIONAL parameter is the URL to which responses are directed. Note that this serves roughly the
     * same purpose as the WS-Addressing <wsa:ReplyTo> header for the WS-Trust SOAP RST messages.
     */
    public static final String PARAM_REPLY = "wreply";

    /**
     * This REQUIRED parameter is the URI of the requesting realm. Note that this serves roughly the same
     * purpose as the AppliesTo element in the WS-Trust SOAP RST messages.
     */
    public static final String PARAM_TREALM = "wtrealm";

    /**
     * This OPTIONAL parameter indicates the freshness requirements. If specified, this indicates the desired
     * maximum age of authentication specified in minutes. An IP/STS SHOULD NOT issue a token with a longer
     * lifetime. If specified as “0” it indicates a request for the IP/STS to re-prompt the user for
     * authentication before issuing the token. Note that this serves roughly the same purpose as the
     * Freshness element in the WS-Trust SOAP RST messages.
     */
    public static final String PARAM_FRESHNESS = "wfresh";

    /**
     * This OPTIONAL parameter indicates the REQUIRED authentication level. Note that this parameter uses the
     * same URIs and is equivalent to the wst:AuthenticationType element in the WS-Trust SOAP RST messages.
     */
    public static final String PARAM_AUTH_TYPE = "wauth";

    /**
     * This OPTIONAL parameter specifies a token request using either a <wst:RequestSecurityToken> element or
     * a full request message as described in WS-Trust. If this parameter is not specified, it is assumed that
     * the responding service knows the correct type of token to return. Note that this can contain the same
     * RST payload as used in WS-Trust RST messages.
     */
    public static final String PARAM_REQUEST = "wreq";

    /**
     * This OPTIONAL parameter indicates the current time at the sender for ensuring freshness. This parameter
     * is the string encoding of time using the XML Schema datetime time using UTC notation. Note that this
     * serves roughly the same purpose as the WS-Security Timestamp elements in the Security headers of the
     * SOAP RST messages.
     */
    public static final String PARAM_CURRENT_TIME = "wct";

    /**
     * This OPTIONAL parameter is an opaque context value that MUST be returned with the issued token if it is
     * passed in the request. Note that this serves roughly the same purpose as the WS-Trust SOAP RST @Context
     * attribute.
     */
    public static final String PARAM_CONTEXT = "wctx";

    /**
     * This OPTIONAL parameter is the URL for the policy which can be obtained using an HTTP GET and
     * identifies the policy to be used related to the action specified in "wa", but MAY have a broader scope
     * than just the "wa". Note that this serves roughly the same purpose as the Policy element in the
     * WS-Trust SOAP RST messages.
     */
    public static final String PARAM_POLICY = "wp";

    /**
     * This OPTIONAL parameter indicates the federation context in which the request is made. This is
     * equivalent to the FederationId parameter in the RST message.
     */
    public static final String PARAM_FED_CONTEXT = "wfed";

    /**
     * This OPTIONAL parameter indicates the encoding style to be used for XML parameter content. If not
     * specified the default behavior is to use standard URL encoding rules
     */
    public static final String PARAM_ENCODING = "wencoding";

    /**
     * This REQUIRED parameter specifies the result of the token issuance. This can take the form of the
     * <wst:RequestSecurityTokenResponse> element or <wst:RequestSecurityTokenResponseCollection> element, a
     * SOAP security token request response (that is, a <S:Envelope>) as detailed in WS-Trust, or a SOAP
     * <S:Fault> element.
     */
    public static final String PARAM_RESULT = "wresult";

    /**
     * This OPTIONAL parameter indicates the account partner realm of the client. This parameter is used to
     * indicate the IP/STS address for the requestor. This may be specified directly as a URL or indirectly as
     * an identifier (e.g. urn: or uuid:). In the case of an identifier the recipient is expected to know how
     * to translate this (or get it translated) to a URL. When the whr parameter is used, the resource, or its
     * local IP/STS, typically removes the parameter and writes a cookie to the client browser to remember
     * this setting for future requests. Then, the request proceeds in the same way as if it had not been
     * provided. Note that this serves roughly the same purpose as federation metadata for discovering IP/STS
     * locations previously discussed.
     */
    public static final String PARAM_HOME_REALM = "whr";

    /**
     * This OPTIONAL parameter specifies a URL for where to find the request expressed as a
     * <wst:RequestSecurityToken> element. Note that this does not have a WS-Trust parallel. The wreqptr
     * parameter MUST NOT be included in a token request if wreq is present.
     */
    public static final String PARAM_REQUEST_PTR = "wreqptr";

    /**
     * This parameter specifies a URL to which an HTTP GET can be issued. The result is a document of type
     * text/xml that contains the issuance result. This can either be the <wst:RequestSecurityTokenResponse>
     * element, the <wst:RequestSecurityTokenResponseCollection> element, a SOAP response, or a SOAP <S:Fault>
     * element.
     */
    public static final String PARAM_RESULT_PTR = "wresultptr";

    public static final Map<String, URI> AUTH_TYPE_MAP;
    static {
        Map<String, URI> aMap = new HashMap<>();
        aMap.put("UNKNOWN", FederationConstants.AUTH_TYPE_UNKNOWN);
        aMap.put("DEFAULT", FederationConstants.AUTH_TYPE_DEFAULT);
        aMap.put("SSL", FederationConstants.AUTH_TYPE_SSL);
        aMap.put("SSL_AND_KEY", FederationConstants.AUTH_TYPE_SSL_AND_KEY);
        aMap.put("SSL_STRONG_PASSWORD", FederationConstants.AUTH_TYPE_SSL_STRONG_PASSWORD);
        aMap.put("SSL_STRONG_PASSWORD_EXPIRATION",
                 FederationConstants.AUTH_TYPE_SSL_STRONG_PASSWORD_EXPIRATION);
        aMap.put("SMARTCARD", FederationConstants.AUTH_TYPE_SMARTCARD);
        AUTH_TYPE_MAP = Collections.unmodifiableMap(aMap);
    }

    /**
     * Unknown level of authentication
     */
    public static final URI AUTH_TYPE_UNKNOWN = URI
        .create("http://docs.oasis-open.org/wsfed/authorization/200706/authntypes/unknown");

    /**
     * Default sign-in mechanisms
     */
    public static final URI AUTH_TYPE_DEFAULT = URI
        .create("http://docs.oasis-open.org/wsfed/authorization/200706/authntypes/default");

    /**
     * Sign-in using SSL
     */
    public static final URI AUTH_TYPE_SSL = URI
        .create("http://docs.oasis-open.org/wsfed/authorization/200706/authntypes/Ssl");

    /**
     * Sign-in using SSL and a security key
     */
    public static final URI AUTH_TYPE_SSL_AND_KEY = URI
        .create("http://docs.oasis-open.org/wsfed/authorization/200706/authntypes/SslAndKey");

    /**
     * Sign-in using SSL and a “strong” password
     */
    public static final URI AUTH_TYPE_SSL_STRONG_PASSWORD = URI
        .create("http://docs.oasis-open.org/wsfed/authorization/200706/authntypes/SslAndStrongPasssword");

    /**
     * Sign-in using SSL and a “strong” password with expiration
     */
    public static final URI AUTH_TYPE_SSL_STRONG_PASSWORD_EXPIRATION = URI
        .create("http://docs.oasis-open.org/wsfed/authorization/200706/authntypes/SslAndStrongPasswordWithExpiration");

    /**
     * Sign-in using Smart Card
     */
    public static final URI AUTH_TYPE_SMARTCARD = URI
        .create("http://docs.oasis-open.org/wsfed/authorization/200706/authntypes/smartcard");

    public static final String METADATA_PATH_URI = "FederationMetadata/2007-06/FederationMetadata.xml";

    private FederationConstants() {
        super();
    }
}
