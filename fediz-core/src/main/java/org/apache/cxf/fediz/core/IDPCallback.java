package org.apache.cxf.fediz.core;

import java.net.URL;

import javax.security.auth.callback.Callback;
import javax.servlet.http.HttpServletRequest;


public class IDPCallback implements Callback {

    private HttpServletRequest request = null;
    private URL issuerUrl = null;
    private String trustedIssuer = null;
    
    public IDPCallback(HttpServletRequest request) {
        super();
        this.request = request;
    }
    
    public IDPCallback(HttpServletRequest request, URL issuerUrl,
            String trustedIssuer) {
        super();
        this.request = request;
        this.issuerUrl = issuerUrl;
        this.trustedIssuer = trustedIssuer;      
    }
    
    public HttpServletRequest getRequest() {
        return request;
    }
    public void setRequest(HttpServletRequest request) {
        this.request = request;
    }
    public URL getIssuerUrl() {
        return issuerUrl;
    }
    public void setIssuerUrl(URL issuerUrl) {
        this.issuerUrl = issuerUrl;
    }
    public String getTrustedIssuer() {
        return trustedIssuer;
    }
    public void setTrustedIssuer(String trustedIssuer) {
        this.trustedIssuer = trustedIssuer;
    }
    
}
