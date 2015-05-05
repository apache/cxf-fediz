<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>

<html>
<head>
<title>IDP SignIn Response Form</title>
</head>
<body>
	<form:form method="POST" id="signinresponseform" name="signinresponseform" action="${fedAction}" htmlEscape="true">
        <input type="hidden" name="wa" value="wsignin1.0" /><br />
        <input type="hidden" name="wresult" value="${fedWResult}" /><br />
        <% String wctx = (String)request.getAttribute("fedWCtx");
           if (wctx != null && !wctx.isEmpty()) { %>
        	<input type="hidden" name="wctx" value="${fedWCtx}" /><br />
	    <% } %>
        <input type="hidden" name="wtrealm" value="${fedWTrealm}" /><br />
  		<noscript>
		<p>Script is disabled. Click Submit to continue.</p>
		<input type="submit" name="_eventId_submit" value="Submit" /><br />
 		</noscript>
	</form:form>
 	<script language="javascript">window.setTimeout('document.forms[0].submit()',0);</script>
</body>
</html>
