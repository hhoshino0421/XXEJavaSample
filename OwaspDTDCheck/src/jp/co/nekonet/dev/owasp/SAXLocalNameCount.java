package jp.co.nekonet.dev.owasp;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

public class SAXLocalNameCount extends DefaultHandler {

    public void startDocument() throws SAXException {
        System.out.println("*** startDocument ***");
    }

    public void endDocument() throws SAXException {
        System.out.println("*** endDocument ***");
    }

    public void startElement(String namespaceURI, String localName,
                             String qName, Attributes atts) {

        System.out.println("startElement(qName): " + qName);
        System.out.println("startElement(localName): " + localName);
        System.out.println("startElement(atts): " + atts.getQName(0));
        System.out.println("startElement(atts): " + atts.getValue(0));
    }

    public void endElement(String namespaceURI, String localName, String qName) {

        System.out.println("endElement(qName): " + qName);
        System.out.println("endElement(localName): " + localName);
    }

    public void characters(char[] ch, int start, int length) {
        System.out.print("characters: ");
        for (int i = 0; i < length; i++) {
            System.out.print(ch[start + i]);
        }
        System.out.println();
    }


}
