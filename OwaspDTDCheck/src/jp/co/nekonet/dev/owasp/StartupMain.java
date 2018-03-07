package jp.co.nekonet.dev.owasp;

public class StartupMain {

    public static void main(String[] argv) {
        //System.out.print("Mewmew");

        DOMTest domTestObj = new DOMTest();
        domTestObj.test();

        SAXTest saxTestObj = new SAXTest();
        saxTestObj.test();


    }


}


