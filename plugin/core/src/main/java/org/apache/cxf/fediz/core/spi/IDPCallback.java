package org.apache.cxf.fediz.core.spi;

import java.net.URL;

import javax.servlet.http.HttpServletRequest;

public class IDPCallback extends AbstractServletCallback {

    private URL issuerUrl = null;
    private String trustedIssuer = null;

    public IDPCallback(HttpServletRequest request) {
        super(request);
    }

    /*public IDPCallback(HttpServletRequest request, URL issuerUrl,
            String trustedIssuer) {
        this(request);
        this.issuerUrl = issuerUrl;
        this.trustedIssuer = trustedIssuer;
    }*/

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
