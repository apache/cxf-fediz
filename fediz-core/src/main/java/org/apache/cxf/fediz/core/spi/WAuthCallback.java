package org.apache.cxf.fediz.core.spi;

import javax.servlet.http.HttpServletRequest;

public class WAuthCallback extends AbstractServletCallback {

    private String wauth = null;

    public WAuthCallback(HttpServletRequest request) {
        super(request);
    }
/*
    public WAuthCallback(HttpServletRequest request, String wauth) {
        this(request);
        this.wauth = wauth;
    }
    */

    public String getWAuth() {
        return wauth;
    }

    public void setWAuth(String wauth) {
        this.wauth = wauth;
    }

}
