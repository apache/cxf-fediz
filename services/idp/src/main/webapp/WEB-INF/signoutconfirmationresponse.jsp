<%@ page import="java.util.Map" %>
<%@ page import="org.apache.cxf.fediz.service.idp.domain.Idp" %>
<%@ page import="org.apache.cxf.fediz.service.idp.beans.SigninParametersCacheAction" %>
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
	<h1>Logout from the following realms?</h1>

    <p>
        <%
            final Idp idpConfig = (Idp) request.getAttribute(SigninParametersCacheAction.IDP_CONFIG);

            @SuppressWarnings("unchecked")
            Map<String, String> rum =
                    (Map<String, String>) request.getSession().getAttribute(SigninParametersCacheAction.REALM_URL_MAP);
            
            Iterator<Map.Entry<String, String>> iterator = rum.entrySet().iterator();
            
            while (iterator.hasNext()) {
                Map.Entry<String, String> next = iterator.next();
                String rpUri = next.getValue();
                if (rpUri != null) {
        %>
        Will logout on RP: <%= rpUri%>
        <br/>
        <%
                }
            }
        %>
        <form:form method="POST" id="signoutconfirmationresponseform" name="signoutconfirmationresponseform">
            <input type="hidden" name="wa" value="wsignout1.0" />
            <input type="hidden" id="execution" name="execution" value="${flowExecutionKey}" />
            <input type="submit" name="_eventId_submit" value="Logout" />
            <input type="submit" name="_eventId_cancel" value="Cancel" />
        </form:form>
    </p>
</body>
</html>
