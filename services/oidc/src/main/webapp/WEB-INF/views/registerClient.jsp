<%@ page import="javax.servlet.http.HttpServletRequest,java.util.Map,java.util.Iterator,org.apache.cxf.fediz.service.oidc.RegisterClient" %>
<%
    RegisterClient reg = (RegisterClient)request.getAttribute("data");
    String basePath = request.getContextPath() + request.getServletPath();
    if (!basePath.endsWith("/")) {
        basePath += "/";
    }
%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>Client Registration Form</title>
    <STYLE TYPE="text/css">
	<!--
	  input {font-family:verdana, arial, helvetica, sans-serif;font-size:20px;line-height:40px;}
	  H1 { text-align: center}
	  div.padded {  
         padding-left: 5em;  
      }   
	-->
</STYLE>
</head>
<body>
<H1>API Client Registration Form</H1>
<br/>
<div class="padded">  
       
     <form action="/fediz-oidc/client/register"
           method="POST">
       <table>    
        <tr>
            <td><big><big><big>Client Name:</big></big></big></td>
            <td>
              <input type="text" name="appName" size="50" value="API Client"/>
            </td>
        </tr>
        <tr>
            <td colspan="2">&nbsp;</td>
        </tr>
        <tr>
            <td><big><big><big>Client Description:</big></big></big></td>
            <td>
              <input type="text" size="50" name="appDescription" 
                     value="API Service Client"/>
            </td>
        </tr>
        <tr>
            <td colspan="2">&nbsp;</td>
        </tr>
        <tr>
            <td><big><big><big>Client Type:</big></big></big></td>
            <td>
               <select name="appType">
				  <option value="confidential" selected>Confidential</option>
				  <option value="public">Public</option>
				</select> 
            </td>
        </tr>
        <tr>
            <td colspan="2">&nbsp;</td>
        </tr>
        <tr>
            <td><big><big><big>Redirect URI:</big></big></big></td>
            <td>
              <input type="text" size="50" name="redirectURI" 
                     value=""/>
            </td>
        </tr>
        <tr>
            <td colspan="2">&nbsp;</td>
        </tr>
        <tr>
            <td><big><big><big>Home Realm:</big></big></big></td>
            <td>
               
               <select name="homeRealm">
                <%
                   if (!reg.getHomeRealms().entrySet().isEmpty()) {
                      Iterator<Map.Entry<String, String>> it = reg.getHomeRealms().entrySet().iterator();
                      Map.Entry<String, String> firstEntry = it.next();
                %>
                      <option value="<%= firstEntry.getKey() %>" selected><%= firstEntry.getValue() %></option>
                <%      
                      while (it.hasNext()) {
                          Map.Entry<String, String> e = it.next();
                %>
                   <option value="<%= e.getKey() %>"><%= e.getValue() %></option>
                <%
                      }
                   } else {
                %>   
                   <option value="" selected>Default</option>
                <%
                   }
                %>
                </select>
            </td>
        </tr>
        <tr>
            <td>
              &nbsp;
            </td>
        </tr>
        </table>
        <table align="center">
        <tr>
            <td colspan="2">
                <input type="submit" value="    Register API Client    "/>
            </td>
        </tr>
        </table>
  </form>
<br/>
<big><big>
<p>
Back to your account <a href="<%= basePath %>"> page</a>
</p>
</big></big> 
</div>
          
</body>
</html>
