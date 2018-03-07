package jp.co.nekonet.dev.owasp;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.FileInputStream;
import java.io.IOException;


public class DOMTest {

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



    private boolean test1_all_disallowed(String fileName) {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        String FEATURE = null;
        try {
            // This is the PRIMARY defense. If DTDs (doctypes) are disallowed, almost all XML entity attacks are prevented
            // Xerces 2 only - http://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl
            FEATURE = "http://apache.org/xml/features/disallow-doctype-decl";
            dbf.setFeature(FEATURE, true);

            DocumentBuilder safebuilder = dbf.newDocumentBuilder();

            Document document = safebuilder.parse(new FileInputStream(fileName));



        } catch (ParserConfigurationException e) {
            // This should catch a failed setFeature feature
            System.out.println("ParserConfigurationException was thrown. The feature '" +
                    FEATURE + "' is probably not supported by your XML processor.");

            return false;

        }
        catch (SAXException e) {
            // On Apache, this should be thrown when disallowing DOCTYPE
            System.out.println("A DOCTYPE was passed into the XML document");

            return false;

        }
        catch (IOException e) {
            // XXE that points to a file that doesn't exist
            System.out.println("IOException occurred, XXE may still possible: " + e.getMessage());

            return false;

        } catch(Exception ee){
            System.out.println("Exception occurred, XXE may still possible: " + ee.getMessage());

            return false;

        }

        //正常終了
        return true;

    }


    private boolean test2_following(String fileName) {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        String FEATURE = null;
        try {

            // If you can't completely disable DTDs, then at least do the following:
            // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-general-entities
            // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-general-entities
            // JDK7+ - http://xml.org/sax/features/external-general-entities
            FEATURE = "http://xml.org/sax/features/external-general-entities";
            dbf.setFeature(FEATURE, false);

            // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-parameter-entities
            // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities
            // JDK7+ - http://xml.org/sax/features/external-parameter-entities
            FEATURE = "http://xml.org/sax/features/external-parameter-entities";
            dbf.setFeature(FEATURE, false);

            // Disable external DTDs as well
            FEATURE = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
            dbf.setFeature(FEATURE, false);

            // and these as well, per Timothy Morgan's 2014 paper: "XML Schema, DTD, and Entity Attacks"
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);

            // And, per Timothy Morgan: "If for some reason support for inline DOCTYPEs are a requirement, then
            // ensure the entity settings are disabled (as shown above) and beware that SSRF attacks
            // (http://cwe.mitre.org/data/definitions/918.html) and denial
            // of service attacks (such as billion laughs or decompression bombs via "jar:") are a risk."

            // remaining parser logic


            DocumentBuilder safebuilder = dbf.newDocumentBuilder();

            Document document = safebuilder.parse(new FileInputStream(fileName));


            //Document doc = parser.getDocument();
            String data1 = document.getElementsByTagName("data1")
                    .item(0).getTextContent();
            String data2 = document.getElementsByTagName("data2")
                    .item(0).getTextContent();

            String outText = data1 + data2;
            System.out.println(outText);



        } catch (ParserConfigurationException e) {
            // This should catch a failed setFeature feature
            System.out.println("ParserConfigurationException was thrown. The feature '" +
                    FEATURE + "' is probably not supported by your XML processor.");

            return false;

        }
        catch (SAXException e) {
            // On Apache, this should be thrown when disallowing DOCTYPE
            System.out.println("A DOCTYPE was passed into the XML document");

            return false;

        }
        catch (IOException e) {
            // XXE that points to a file that doesn't exist
            System.out.println("IOException occurred, XXE may still possible: " + e.getMessage());

            return false;

        } catch(Exception ee){
            System.out.println("Exception occurred, XXE may still possible: " + ee.getMessage());

            return false;

        }

        //正常終了
        return true;

    }



    private boolean test_zero(String fileName) {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        try {
            DocumentBuilder safebuilder = dbf.newDocumentBuilder();

            Document document = safebuilder.parse(new FileInputStream(fileName));


            //Document doc = parser.getDocument();
            String data1 = document.getElementsByTagName("data1")
                    .item(0).getTextContent();
            String data2 = document.getElementsByTagName("data2")
                    .item(0).getTextContent();

            String outText = data1 + data2;
            System.out.println(outText);
        } catch (ParserConfigurationException e) {
            // This should catch a failed setFeature feature
            System.out.println("ParserConfigurationException was thrown. The feature '" +
                     "' is probably not supported by your XML processor.");

            return false;

        }
        catch (SAXException e) {
            // On Apache, this should be thrown when disallowing DOCTYPE
            System.out.println("A DOCTYPE was passed into the XML document");

            return false;

        }
        catch (IOException e) {
            // XXE that points to a file that doesn't exist
            System.out.println("IOException occurred, XXE may still possible: " + e.getMessage());

            return false;

        } catch(Exception ee){
            System.out.println("Exception occurred, XXE may still possible: " + ee.getMessage());

            return false;

        }

        //正常終了
        return true;

    }
}
