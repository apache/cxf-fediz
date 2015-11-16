<%@ page import="javax.servlet.http.HttpServletRequest, org.apache.cxf.rs.security.oauth2.common.OOBAuthorizationResponse" %>

<%
    OOBAuthorizationResponse authResponse = (OOBAuthorizationResponse)request.getAttribute("data");
    String basePath = request.getContextPath() + request.getServletPath();
    if (!basePath.endsWith("/")) {
        basePath += "/";
    } 
%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>Authorization Code Response</title>
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
<%= authResponse.getUserId() %>, here is an authorization code for a public <%= authResponse.getClientDescription() %> with id <%= authResponse.getClientId() %>
</h1>
<em></em>
<br/>
<table border="1">
    <tr><th><big><big>Code</big></big></th><th><big><big>Expires In</big></big></th></tr> 
    <tr>
           <td><big><big><%= authResponse.getAuthorizationCode() %></big></big></td>
           <td><big><big><%= authResponse.getExpiresIn() %></big></big></td>
    </tr>
    
</table>

<br/>
Please enter the code into this public client application.
<br/> 
<p>
<big><big>
</p>
<br/>
<p>
Back to <a href="<%= basePath %>client">Client Registration page</a>
</p>
</big></big>
</div>
</body>
</html>

