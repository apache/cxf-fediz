package org.apache.cxf.fediz.example;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimCollection;
import org.apache.cxf.fediz.tomcat.FederationPrincipal;
import org.w3c.dom.Element;

public class FederationServlet extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = -9019993850246851112L;

	public void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		response.setContentType("text/html");
		PrintWriter out = response.getWriter();

		out.println("<html>");
		out.println("<head><title>WS Federation Tomcat Examples</title></head>");
		out.println("<body>");
		out.println("<h1>Hello World</h1>");
		out.println("Hello world<br>");
		out.println("Request url: " + request.getRequestURL().toString() + "<p>");
		

		
		out.println("<br><b>User</b><p>");
		Principal p = request.getUserPrincipal();
		if (p != null) {
			out.println("Principal: " + p.getName() + "<p>");
		}
		
		out.println("<br><b>Roles</b><p>");
		List<String> roleListToCheck = Arrays.asList("Admin", "Manager", "User", "Authenticated");
		for (String item: roleListToCheck) {
			out.println("Has role '" + item + "': " + ((request.isUserInRole(item)) ? "<b>yes</b>" : "no") + "<p>" );
		}
		
		if (p instanceof FederationPrincipal) {
			FederationPrincipal fp = (FederationPrincipal)p;
			
			out.println("<br><b>Claims</b><p>");
			ClaimCollection claims = fp.getClaims();
			for (Claim c: claims) {
				out.println(c.getClaimType().toString() + ": " + c.getValue() + "<p>");
			}
		}
		else {
			out.println("Principal is not instance of FederationPrincipal");
		}
		
		
		//FederationResponse fd = (FederationResponse)request.getSession().getAttribute(FederationAuthenticator.FEDERATION_NOTE);
		
		Element el = SecurityTokenThreadLocal.getToken();
		if (el != null) {
			out.println("<p>Bootstrap token...");
			String token = null;
			try {
				TransformerFactory transFactory = TransformerFactory.newInstance();
				Transformer transformer = transFactory.newTransformer();
				StringWriter buffer = new StringWriter();
				transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
				transformer.transform(new DOMSource(el),
				      new StreamResult(buffer));
				token = buffer.toString();
				out.println("<p>" + StringEscapeUtils.escapeXml(token));
			} catch (Exception ex) {
				out.println("<p>Failed to transform cached element to string: " + ex.toString());
			}
		}
		else {
			out.println("<p>Bootstrap token not cached in thread local storage");
		}
		
		out.println("</body>");
	}

}