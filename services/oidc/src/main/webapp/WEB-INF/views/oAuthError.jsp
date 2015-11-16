<%@ page import="javax.servlet.http.HttpServletRequest, org.apache.cxf.rs.security.oauth2.common.OAuthError" %>

<%
    OAuthError error = (OAuthError)request.getAttribute("data");
    String basePath = request.getContextPath() + request.getServletPath();
    if (!basePath.endsWith("/")) {
        basePath += "/";
    } 
%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>Authorization Code Error Response</title>
    <STYLE TYPE="text/css">
	<!--
	  div.padded {  
         padding-left: 2em;  
      }   
	-->
</STYLE>
</head>
<body>
<div class="padded">

<h1>
Authorization error: <%= error.getError() %> 
</h1>
<br/>
<p>
Back to <a href="<%= basePath %>client">Client Registration page</a>
</p>
</big></big>
</div>
</body>
</html>

