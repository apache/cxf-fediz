<%@page import="org.opensaml.soap.wsfed.WSFedConstants"%>
<%@ page import="java.util.Map" %>
<%@ page import="org.apache.cxf.fediz.service.idp.beans.SigninParametersCacheAction" %>
<%@ page import="org.apache.cxf.fediz.service.idp.domain.Application" %>
<%@ page import="org.apache.cxf.fediz.core.FederationConstants" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.Iterator" %>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<title>IDP SignOut Response Page</title>
</head>
<body>
    <%
        @SuppressWarnings("unchecked")
        Map<String, Application> apps =
                (Map<String, Application>) request.getAttribute(SigninParametersCacheAction.ACTIVE_APPLICATIONS);
    	String wreply = (String) request.getAttribute("wreply");

        if (apps == null) {
    %>
	        <p>You have already logged out</p>
    <%
        } else {
    %>
            <h1>CXF Fediz IDP successful logout.</h1>
        
            <p>
    <%
            Iterator<Map.Entry<String, Application>> iterator = apps.entrySet().iterator();
            
            while (iterator.hasNext()) {
                Application next = iterator.next().getValue();
                if (next != null) {
    %>
                    <%= next.getServiceDisplayName() %> 
                    <img src="<%=next.getPassiveRequestorEndpoint() + "?" + FederationConstants.PARAM_ACTION 
                        + "=" + FederationConstants.ACTION_SIGNOUT_CLEANUP %>"/>
                    <br/>
    <%
                }
            }
    %>
	        </p>
    <%
        }
        if (wreply != null && !wreply.isEmpty()) {
    %>
    <p><a href="<%= wreply%>">continue</a></p>
    <%
        }
    %>
</body>
</html>
