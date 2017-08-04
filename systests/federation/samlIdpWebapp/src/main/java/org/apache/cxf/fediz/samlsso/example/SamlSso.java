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

package org.apache.cxf.fediz.samlsso.example;


import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.zip.DataFormatException;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriBuilder;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLStreamException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.common.util.Base64Exception;
import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.helpers.IOUtils;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.rs.security.saml.DeflateEncoderDecoder;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.AudienceRestrictionBean;
import org.apache.wss4j.common.saml.bean.ConditionsBean;
import org.apache.wss4j.common.saml.bean.SubjectConfirmationDataBean;
import org.apache.wss4j.common.util.DOM2Writer;
import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;

/**
 * A mock IdP for SAML SSO. The user is already authenticated via HTTP/BA.
 */
@Path("/samlsso")
public class SamlSso {

    static {
        OpenSAMLUtil.initSamlEngine();
    }

    private final DocumentBuilderFactory docBuilderFactory;
    private MessageContext messageContext;

    public SamlSso() {
        docBuilderFactory = DocumentBuilderFactory.newInstance();
        docBuilderFactory.setNamespaceAware(true);
    }

    @POST
    public javax.ws.rs.core.Response login(@FormParam("SAMLRequest") String samlRequest,
        @FormParam("RelayState") String relayState) throws Exception {

        return login(samlRequest, relayState, "POST");
    }

    @GET
    public javax.ws.rs.core.Response login(@QueryParam("SAMLRequest") String samlRequest,
            @QueryParam("RelayState") String relayState, @QueryParam("binding") String binding) throws Exception {

        AuthnRequest request = extractRequest(samlRequest);

        String racs = request.getAssertionConsumerServiceURL();
        String requestIssuer = request.getIssuer().getValue();

        // Create the response
        Element response = createResponse(request.getID(), racs, requestIssuer);
        boolean redirect = "REDIRECT".equals(binding);
        String responseStr = encodeResponse(response, redirect);

        if (redirect) {
            return redirectResponse(relayState, racs, responseStr);
        } else {
            return postBindingResponse(relayState, racs, responseStr);
        }
    }

    @Context
    public void setMessageContext(MessageContext mc) {
        this.messageContext = mc;
    }

    protected Element createResponse(String requestID, String racs, String requestIssuer) throws Exception {
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        Document doc = docBuilder.newDocument();

        Status status =
            SAML2PResponseComponentBuilder.createStatus(
                "urn:oasis:names:tc:SAML:2.0:status:Success", null
            );
        String issuer = messageContext.getUriInfo().getAbsolutePath().toString();
        Response response =
            SAML2PResponseComponentBuilder.createSAMLResponse(requestID, issuer, status);

        // Create an AuthenticationAssertion
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setIssuer(issuer);
        String user = messageContext.getSecurityContext().getUserPrincipal().getName();
        callbackHandler.setSubjectName(user);

        // Subject Confirmation Data
        SubjectConfirmationDataBean subjectConfirmationData = new SubjectConfirmationDataBean();
        subjectConfirmationData.setAddress(messageContext.getHttpServletRequest().getRemoteAddr());
        subjectConfirmationData.setInResponseTo(requestID);
        subjectConfirmationData.setNotAfter(new DateTime().plusMinutes(5));
        subjectConfirmationData.setRecipient(racs);
        callbackHandler.setSubjectConfirmationData(subjectConfirmationData);

        // Audience Restriction
        ConditionsBean conditions = new ConditionsBean();
        conditions.setTokenPeriodMinutes(5);

        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.setAudienceURIs(Collections.singletonList(requestIssuer));
        conditions.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(conditions);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);

        Crypto issuerCrypto = CryptoFactory.getInstance("stsKeystoreB.properties");
        assertion.signAssertion("realmb", "realmb", issuerCrypto, false);

        response.getAssertions().add(assertion.getSaml2());

        Element policyElement = OpenSAMLUtil.toDom(response, doc);
        doc.appendChild(policyElement);

        return policyElement;
    }

    protected String encodeResponse(Element response, boolean redirect) throws IOException {
        String responseMessage = DOM2Writer.nodeToString(response);
        System.out.println("RESP: " + responseMessage);

        byte[] deflatedBytes = null;
        if (redirect) {
            DeflateEncoderDecoder encoder = new DeflateEncoderDecoder();
            deflatedBytes = encoder.deflateToken(responseMessage.getBytes(StandardCharsets.UTF_8));
        } else {
            deflatedBytes = responseMessage.getBytes(StandardCharsets.UTF_8);
        }

        return Base64Utility.encode(deflatedBytes);
    }

    protected AuthnRequest extractRequest(String samlRequest) throws Base64Exception,
        DataFormatException, XMLStreamException, UnsupportedEncodingException, WSSecurityException {
        byte[] deflatedToken = Base64Utility.decode(samlRequest);

        InputStream tokenStream = new DeflateEncoderDecoder().inflateToken(deflatedToken);

        Document responseDoc = StaxUtils.read(new InputStreamReader(tokenStream, StandardCharsets.UTF_8));
        AuthnRequest request =
            (AuthnRequest)OpenSAMLUtil.fromDom(responseDoc.getDocumentElement());
        System.out.println(DOM2Writer.nodeToString(responseDoc));
        return request;
    }

    protected javax.ws.rs.core.Response postBindingResponse(String relayState, String racs, String responseStr)
        throws IOException {
        InputStream inputStream = this.getClass().getResourceAsStream("/TemplateSAMLResponse.xml");
        String responseTemplate = IOUtils.toString(inputStream, StandardCharsets.UTF_8.name());
        inputStream.close();

        // Perform Redirect to RACS
        responseTemplate = responseTemplate.replace("%RESPONSE_URL%", racs);
        responseTemplate = responseTemplate.replace("%SAMLResponse%", responseStr);
        responseTemplate = responseTemplate.replace("%RelayState%", relayState);

        return javax.ws.rs.core.Response.ok(responseTemplate).type(MediaType.TEXT_HTML).build();
    }

    protected javax.ws.rs.core.Response redirectResponse(String relayState, String racs, String responseStr) {
        // Perform Redirect to RACS
        UriBuilder ub = UriBuilder.fromUri(racs);
        ub.queryParam("SAMLResponse", responseStr);
        ub.queryParam("RelayState", relayState);

        return javax.ws.rs.core.Response.seeOther(ub.build()).build();
    }

}


