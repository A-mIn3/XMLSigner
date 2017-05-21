package test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class XMLSignatureVerifier {
	
	private String signedXmlfilename ;
	private boolean valid;
	
	public XMLSignatureVerifier(String signedXmlfilename) throws FileNotFoundException{
			if(!Files.exists(Paths.get(signedXmlfilename)))
				throw new FileNotFoundException();
			else{
				this.signedXmlfilename=signedXmlfilename;	
				this.valid=false;
			}
	}
	
	
	public boolean  isValid(){
		return valid;
	}
	
	private void setValid(boolean valide) throws Exception{
		verify();
		this.valid =valide;
	}
	
	private void verify() throws Exception{
		
		Document document = null;
		NodeList nodelist = null;
		DOMValidateContext context = null;
		XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
		DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
		builderFactory.setNamespaceAware(true);
		try {
			 builderFactory.newDocumentBuilder().parse(signedXmlfilename);

		} catch (SAXException | IOException | ParserConfigurationException e) {
				System.out.println(e.getMessage());
		}
		
		nodelist = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		if (nodelist.getLength() == 0) 
		    throw new Exception("Le document ne contient pas un element signature.");
		
		context = new DOMValidateContext(new X509KeySelector(), nodelist.item(0));
		
		XMLSignature signature = factory.unmarshalXMLSignature(context);
		this.setValid(signature.validate(context));
		
		
		
		 
	}

}
