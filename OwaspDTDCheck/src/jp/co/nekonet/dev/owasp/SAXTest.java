package jp.co.nekonet.dev.owasp;

import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.IOException;

public class SAXTest {

    public void test() {

        String fileName_1 = "/home/hhoshino/workspace/IntelliJ_workspace/OwaspDTDCheck/test1.xml";
        String fileName_2 = "/home/hhoshino/workspace/IntelliJ_workspace/OwaspDTDCheck/test2.xml";
        String fileName_3 = "/home/hhoshino/workspace/IntelliJ_workspace/OwaspDTDCheck/test3.xml";

        boolean ret_test0;
        ret_test0 = test_zero(fileName_1);
        if (ret_test0) {
            System.out.println("test0 file1 Success");
        } else {
            System.out.println("test0 file1 Fatal");
        }

        ret_test0 = test_zero(fileName_2);
        if (ret_test0) {
            System.out.println("test0 file2 Success");
        } else {
            System.out.println("test0 file2 Fatal");
        }

        ret_test0 = test_zero(fileName_3);
        if (ret_test0) {
            System.out.println("test0 file3 Success");
        } else {
            System.out.println("test0 file3 Fatal");
        }


        boolean ret_test1;
        ret_test1 = test1_all_disallowed(fileName_1);
        if (ret_test1) {
            System.out.println("test1 file1 Success");
        } else {
            System.out.println("test1 file1 Fatal");
        }

        ret_test1 = test1_all_disallowed(fileName_2);
        if (ret_test1) {
            System.out.println("test1 file2 Success");
        } else {
            System.out.println("test1 file2 Fatal");
        }

        ret_test1 = test1_all_disallowed(fileName_3);
        if (ret_test1) {
            System.out.println("test1 file3 Success");
        } else {
            System.out.println("test1 file3 Fatal");
        }

        boolean ret_test2;
        ret_test2 = test2_following(fileName_1);
        if (ret_test2) {
            System.out.println("test2 file1 Success");
        } else {
            System.out.println("test2 file1 Fatal");
        }

        ret_test2 = test2_following(fileName_2);
        if (ret_test2) {
            System.out.println("test2 file2 Success");
        } else {
            System.out.println("test2 file2 Fatal");
        }

        ret_test2 = test2_following(fileName_3);
        if (ret_test2) {
            System.out.println("test2 file3 Success");
        } else {
            System.out.println("test2 file3 Fatal");
        }

    }


    private boolean test_zero(String fileName) {

        SAXParserFactory spf = SAXParserFactory.newInstance();

        try {

            SAXParser saxParser = spf.newSAXParser();
            XMLReader xmlReader = saxParser.getXMLReader();
            xmlReader.setContentHandler(new SAXLocalNameCount());
            xmlReader.parse(fileName);

        } catch (ParserConfigurationException pe) {
            System.out.println("ParserConfigurationException was thrown. The feature '" +
                    "' is probably not supported by your XML processor.");

            return false;

        } catch (SAXException se) {
            System.out.println("A DOCTYPE was passed into the XML document");

            return false;

        } catch (IOException ie) {

            System.out.println("IOException occurred, XXE may still possible: " + ie.getMessage());

            return false;

        } catch (Exception ee) {
            System.out.println("Exception occurred, XXE may still possible: " + ee.getMessage());

            return false;
        }

        //正常終了
        return true;
    }


    private boolean test1_all_disallowed(String fileName) {


        SAXParserFactory spf = SAXParserFactory.newInstance();
        String FEATURE = null;

        try {
            FEATURE = "http://apache.org/xml/features/disallow-doctype-decl";
            spf.setFeature(FEATURE, true);

            SAXParser saxParser = spf.newSAXParser();
            XMLReader xmlReader = saxParser.getXMLReader();
            xmlReader.setContentHandler(new SAXLocalNameCount());
            xmlReader.parse(fileName);

        } catch (ParserConfigurationException pe) {
            System.out.println("ParserConfigurationException was thrown. The feature '" +
                    "' is probably not supported by your XML processor.");

            return false;

        } catch (SAXException se) {
            System.out.println("A DOCTYPE was passed into the XML document");

            return false;

        } catch (IOException ie) {

            System.out.println("IOException occurred, XXE may still possible: " + ie.getMessage());

            return false;

        } catch (Exception ee) {
            System.out.println("Exception occurred, XXE may still possible: " + ee.getMessage());

            return false;
        }

        //正常終了
        return true;

    }

    private boolean test2_following(String fileName) {

        SAXParserFactory spf = SAXParserFactory.newInstance();
        String FEATURE = null;

        try {

            // If you can't completely disable DTDs, then at least do the following:
            // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-general-entities
            // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-general-entities
            // JDK7+ - http://xml.org/sax/features/external-general-entities
            FEATURE = "http://xml.org/sax/features/external-general-entities";
            spf.setFeature(FEATURE, false);

            // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-parameter-entities
            // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities
            // JDK7+ - http://xml.org/sax/features/external-parameter-entities
            FEATURE = "http://xml.org/sax/features/external-parameter-entities";
            spf.setFeature(FEATURE, false);

            // Disable external DTDs as well
            FEATURE = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
            spf.setFeature(FEATURE, false);

            // and these as well, per Timothy Morgan's 2014 paper: "XML Schema, DTD, and Entity Attacks"
            spf.setXIncludeAware(false);
            //spf.setExpandEntityReferences(false);

            // And, per Timothy Morgan: "If for some reason support for inline DOCTYPEs are a requirement, then
            // ensure the entity settings are disabled (as shown above) and beware that SSRF attacks
            // (http://cwe.mitre.org/data/definitions/918.html) and denial
            // of service attacks (such as billion laughs or decompression bombs via "jar:") are a risk."



            SAXParser saxParser = spf.newSAXParser();
            XMLReader xmlReader = saxParser.getXMLReader();
            xmlReader.setContentHandler(new SAXLocalNameCount());
            xmlReader.parse(fileName);

        } catch (ParserConfigurationException pe) {
            System.out.println("ParserConfigurationException was thrown. The feature '" +
                    "' is probably not supported by your XML processor.");

            return false;

        } catch (SAXException se) {
            System.out.println("A DOCTYPE was passed into the XML document");

            return false;

        } catch (IOException ie) {

            System.out.println("IOException occurred, XXE may still possible: " + ie.getMessage());

            return false;

        } catch (Exception ee) {
            System.out.println("Exception occurred, XXE may still possible: " + ee.getMessage());

            return false;
        }

        //正常終了
        return true;


    }

}


