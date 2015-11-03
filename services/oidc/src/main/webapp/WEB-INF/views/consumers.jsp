<%@ page import="javax.servlet.http.HttpServletRequest, org.apache.cxf.rs.security.oauth2.client.Consumer, org.apache.cxf.rs.security.oauth2.client.Consumers" %>

<%
    Consumers regs = (Consumers)request.getAttribute("data");
    String basePath = request.getContextPath() + request.getServletPath();
    if (!basePath.endsWith("/")) {
        basePath += "/";
    } 
%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>API Client Registration Confirmation</title>
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

<h1>Registered API Clients</h1>
<em></em>
<br/>
<table border="1">
    <tr><th><big><big>Client Name</big></big></th><th><big><big>Client Identifier</big></big></th><th><big><big>Client Secret</big></big></th><th><big><big>PreAuthorized Token</big></big></th><th><big><big>PreAuthorized Code</big></big></th></tr> 
    <%
       for (Consumer entry : regs.getConsumers()) {
    %>
       <tr>
           <td><big><big><%= entry.getDescription() %></big></big></td>
           <td><big><big><input type="text" name="clientId" readonly="readonly" value="<%= entry.getKey() %>"/></big></big></td>
           <%
              if (entry.getSecret() != null) {
           %>
           <td><big><big><%= entry.getSecret() %></big></big></td>
           <%
              } else {
           %>
              <td><big><big>Unavailable for public client</big></big></td>
           <%
              } 
           %>
       </tr>
    <%   
       }
    %> 
    
</table>

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

