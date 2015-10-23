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
<title>IDP SignOut Confirmation Response Page</title>
</head>
<body>
    <%
        @SuppressWarnings("unchecked")
        Map<String, Application> rcm =
        (Map<String, Application>) request.getSession().getAttribute(SigninParametersCacheAction.ACTIVE_APPLICATIONS);
    	String wreply = (String) request.getAttribute("wreply");

        if (rcm == null) {
    %>
	        <p>You have already logged out</p>
    <%
        } else {
    %>
	        <h1>Logout from the following Applications?</h1>
			<div>	   
    <%
            Iterator<Map.Entry<String, Application>> iterator = rcm.entrySet().iterator();
                
            while (iterator.hasNext()) {
                Application next = iterator.next().getValue();
                if (next != null) {
    %>
                    <%= next.getServiceDisplayName() %>
                    <br/>
    <%
                }
            }
        }
        
        if (rcm != null && !rcm.isEmpty()) {
    %>
	    	</div>
	    	<br/>
	    	<br/>
	        <form:form method="POST" id="signoutconfirmationresponseform" name="signoutconfirmationresponseform">
	            <input type="hidden" name="wa" value="wsignout1.0" />
	            <input type="hidden" id="execution" name="execution" value="${flowExecutionKey}" />
	            <input type="submit" name="_eventId_submit" value="Logout" />
			    <%     
			        if (wreply != null && !wreply.isEmpty()) {
			    %>
			    <input type="hidden" name="wreply" value="<%= wreply%>" />        
	            <input type="submit" name="_eventId_cancel" value="Cancel" />
	            <%     
			        }
			    %>
	        </form:form>
    <%     
        }
    %>
</body>
</html>
