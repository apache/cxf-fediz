package org.apache.cxf.fediz.example;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.w3c.dom.Element;

/**
 * Add security token to thread local
 *
 * @deprecated  Use filter shipped with SAFT
 */
@Deprecated
public class FederationFilter implements Filter {

    private static final String DEFAULT_SECURITY_TOKEN_ATTR = "org.apache.fediz.SECURITY_TOKEN";
    private static final String SECURITY_TOKEN_ATTR_CONFIG = "security.token.attribute";

    private String securityTokenAttr = DEFAULT_SECURITY_TOKEN_ATTR;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        String attrName = filterConfig.getInitParameter(SECURITY_TOKEN_ATTR_CONFIG);
        if (attrName != null) {
            securityTokenAttr = attrName;
        }

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        if (request instanceof HttpServletRequest) {
            HttpServletRequest hrequest = (HttpServletRequest)request;
            Element el = (Element)hrequest.getSession().getAttribute(securityTokenAttr);
            if (el != null) {
                try
                {
                    SecurityTokenThreadLocal.setToken(el);
                    chain.doFilter(request, response);
                } finally {
                    SecurityTokenThreadLocal.setToken(null);
                }		
            } else {
                chain.doFilter(request, response);
            }

        } else {
            chain.doFilter(request, response);
        }
    }

    @Override
    public void destroy() {
        // TODO Auto-generated method stub

    }

}
