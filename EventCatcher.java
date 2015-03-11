
/*
 *------------------------------------------------------------------
 * EventCatcher.java
 *
 * Copyright 2015 Sean Leary
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. *------------------------------------------------------------------
 */

import java.net.*;
import java.io.*;
import java.util.*;
import java.security.cert.*;
import javax.net.ssl.*;


/**
 * EventCatcher opens a subscription on a sensor for events 
 */

public class EventCatcher
{

    /**
    * set to true to get more info
    */
    boolean verbose = false;

    /**
    * sensor uri
    */
    StringBuffer uri;

    /**
    * control trans request xml content data 
    */
    StringBuffer sensorXmlMsg;

    /**
    * This is the username of the webserver account on the sensor.  If not specified
    * then the browser will be reponsible for obtaining the username.
    */
    StringBuffer sensorUsername;

    /**
    * This is the password of the webserver account on the sensor.  If not specified
    * then the browser will be reponsible for obtaining the password.
    */
    StringBuffer sensorPassword;

    /**
    * This is the session cookie returned by the server
    */
    StringBuffer sessionCookie = new StringBuffer();

    String openParams = new String();
    String getParams = new String();
    String subscriptionId = new String();

    // *********** Handling of TrustStore *************

    /**
    * This function installs the certification and hostname verification objects
    */
    static
    {
        // Create a trust manager that does not validate certificate chains
        X509TrustManager tm = new MyX509TrustManager();
        TrustManager[] trustAllCerts = {tm};

        // Install the all-trusting trust manager
        try
        {
            SSLContext sc = SSLContext.getInstance( "TLS" );
            sc.init( null, trustAllCerts, new java.security.SecureRandom() );
            HttpsURLConnection.setDefaultSSLSocketFactory( sc.getSocketFactory() );
        }
        catch ( Exception e ) {
            // System.out.println("Exception occured while handling Trust Manager ["
            // +e.toString()+ "]");
        }

        // Create a hostname verifier that will always return true
        HostnameVerifier hv = new MyHostnameVerifier();

        // Install the always-true verifier
        try
        {
            HttpsURLConnection.setDefaultHostnameVerifier( hv );
        }
        catch ( Exception e ) {
            // System.out.println("Exception occured while handling Default HostName verifier ["
            // +e.toString()+ "]");
        }
    }



   /**
    * class constructor
    */
    public EventCatcher 
    (String uri_, String username_, String password_, boolean verbose_,
    String openParams_, String getParams_)
    {
        uri = new StringBuffer(uri_);
        sensorUsername = new StringBuffer(username_);
        sensorPassword = new StringBuffer(password_);
        sensorXmlMsg = new StringBuffer();
        verbose = verbose_;
        openParams = openParams_;
        getParams = getParams_;
    }

   /**
    * This function sends an unending sequence of event requests, starting with an action=open request.
    */
    public void processEvents()
    {
        String url = uri.toString();

        StringBuffer openUri = new StringBuffer(url+"?action=open&sessionCookies=yes");

        // action=open params
        if (openParams.length() > 0) {
            openUri.append(new StringBuffer("&"));
            openUri.append(new StringBuffer(openParams));
        }
        uri = openUri;
        StringBuffer str = new StringBuffer();
        boolean ok = processRdep(str);

        StringBuffer getUri = new StringBuffer(url+"?action=get");

        // action=get params
        if (getParams.length() > 0) {
            getUri.append(new StringBuffer("&"));
            getUri.append(new StringBuffer(getParams));
        }
        if (subscriptionId.length() > 0) {
            getUri.append(new StringBuffer("&subscriptionId="));
            getUri.append(new StringBuffer(subscriptionId));
        }
        uri = getUri;

        while (ok) {
            str = new StringBuffer();
            ok = processRdep(str);
            boolean eventsFound = true;
            // 5.0 check
            if (str.toString().indexOf("<sd:events></sd:events>") != -1) {
                eventsFound = false;
            // 4.x check
            } else if (str.toString().indexOf("schemaVersion=\"1.00\"></events>") != -1) {
                eventsFound = false;
            }
            if (eventsFound) {
                // there must be nontrivial content
                // System.out.println(str.toString()+"\n");
                String iStr = str.toString();
                StringBuffer oStr = new StringBuffer();
                int indent = 0;
                int start = 1;
                int end = 2;
                int state = 0;
                boolean first = true;
                for (int i = 0; i < iStr.length(); ++i) {
                    char c = iStr.charAt(i);
                    if (c == '<') {
                        if (first) {
                            first = false;
                        } else {
                            if (iStr.charAt(i+1) == '/') {
                                if (state == end) {
                                    --indent;
                                    oStr.append("\n");
                                    for (int j = 0; j < indent; ++j)
                                        oStr.append(' ');
                                }
                                state = end;
                            } else {
                                if (state == start) 
                                   ++indent;
                                oStr.append("\n");
                                for (int j = 0; j < indent; ++j)
                                    oStr.append(' ');
                                state = start;
                            }
                        } 
                    }
                    oStr.append(c);
                }
                System.out.println(oStr.toString());

            }
            try {
                Thread.sleep(1000);
            } catch (Exception e) {}
        }
        

    }

   /**
    * This function sends a sensor rdep request and prints the request and response
    */

    public boolean processRdep (StringBuffer str)
    {


        try {
            if (verbose)
                System.out.println("\nRequest URI [" +uri+ "]\n");


            InputStream is = dispatchIdsMessage(uri.toString(), sensorXmlMsg.toString());
            InputStreamReader in =  new InputStreamReader(is);
            BufferedReader reader = new BufferedReader(in);
            String line = null;
            while((line = reader.readLine()) != null) {
                str.append(line);
                // str.append('\n');
            }
            if (sessionCookie.length() > 0 && verbose)
                System.out.println("SessionCookie [" +sessionCookie+ "]\n");

            if (verbose)
                System.out.println("Response [" +str+ "]");

            // check for useful response info 
            String sid = new String ("<sd:subscriptionId>");
            int indx = str.toString().indexOf(sid);
            if (indx != -1) {
                int indx1 = indx + sid.toString().length();
                int indx2 = str.toString().indexOf('<', indx1);
                if (verbose) 
                    System.out.println("indx1 [" +indx1+ "] indx2 [" +indx2+ "]");
                subscriptionId = str.toString().substring(indx1, indx2);
                if (verbose)
                    System.out.println("subscriptionId [" +subscriptionId+ "]");
            }




            return true;
        }
        catch (Exception e) {
            System.out.println("Error when sending message to sensor [" +e.getMessage()+ "]");
            return false;
        }


    }


    /****************************** Internal functions for use by class *****************************/

   /**
    *
    * This function dispatches a message to the sensor and receives a response.
    *
    * @param uri the complete URI string
    *
    * @param xmlMsg contains the XML request data.
    *
    * @param responseParameters output, contains the RDEP HTTP header parameter pairs.
    *
    * @return The input stream for the response
    *
    * @throws Exception
    */
    private InputStream dispatchIdsMessage (String uri, String xmlMsg) throws Exception
    {
        URL url = new URL(uri);
        HttpURLConnection httpConn = getURLobject(uri, xmlMsg, url);

        if (sessionCookie.length() > 0) {
            httpConn.setRequestProperty("Cookie", sessionCookie.toString());
            if (verbose) {
                System.out.println("   key [Cookie]");
                System.out.println("      value [" +sessionCookie+ "]");
            }
        }

        httpConn.connect();

        if (xmlMsg != null && xmlMsg.length() > 0)
        {
            OutputStreamWriter wr = new OutputStreamWriter( httpConn.getOutputStream() );
            wr.write(xmlMsg.toString());
            wr.flush();
            wr.close();
        }
        String cookieHeader = httpConn.getHeaderField("Set-Cookie");
        if(cookieHeader != null)
        {
            int index = cookieHeader.indexOf(";");
            if(index >= 0)
            {
                sessionCookie = new StringBuffer(cookieHeader.substring(0, index));
            }
        }

        // 4.0 sensor response params
        String params = httpConn.getHeaderField("X-Cisco-Rdep-Parameters");
        if(params != null)
        {
            if (verbose) 
                System.out.println("response params found [" +params+ "]");
            boolean moreParams = true;
            while (moreParams) {
                int index = params.indexOf("=");
                String key = params.substring(0, index);
                String value = params.substring(index+1);
                int index1 = params.indexOf("+");
                if (index1 > 0) {
                    value = params.substring(index+1, index1);
                } else {
                    moreParams = false;
                }
                if (verbose)
                    System.out.println("= index [" +index+ "] + index [" +index1+ "] key [" +key+ "] value [" +value+ "]");
                if ("subscriptionId".equals(key)) {
                    if (verbose)
                        System.out.println("subscriptionId [" +value+ "]");
                    subscriptionId = value;
                } else if ("missed-events".equals(key) && "true".equals(value)) {
                    System.out.println("Events were missed!");
                } else {
                    break;
                }
                if (moreParams)
                    params = params.substring(index1+1);
            }
        }
        if (verbose) {
            System.out.println("Header response lines");
            Map map = httpConn.getHeaderFields();
            if (map != null) {
                Set keySet = map.keySet();
                if (keySet != null) {
                    Iterator it = keySet.iterator();
                    while (it.hasNext()) {
                        String key = (String)it.next();
                        System.out.println("   key [" +key+ "]");
                        List list = (List)map.get(key);
                        if (list != null) {
                            Iterator it1 = list.iterator();
                            while (it1.hasNext()) {
                                String value = (String)it1.next();
                                System.out.println("         value [" +value+ "]");
                            }
                        }
                    }
                }
            }
        }

        InputStream response;
        try { 
            response =  httpConn.getInputStream();
            // httpConn.disconnect();
        } catch (IOException e) {
            System.out.println("exception");
            throw e;
        }

        return response;

    }

   /**
    * This function builds a http header for a sensor request
    * @param uri the complete URI string for this sensor request
    * @param xmlMsg optional, the XML content for this request
    * @param url the URL object for this connection
    * @return an initialized HttpURLConnection
    * @throws exception with appropriate error msg if response document contains error msg.
    */
    private HttpURLConnection getURLobject (String uri, String xmlMsg, URL url) throws Exception
    {
        URLConnection urlcon = url.openConnection();
        HttpURLConnection conn = (HttpURLConnection) urlcon;
        //  ******** Filling of Default Request Header Properties  ************
        conn.setUseCaches( false );
        conn.setFollowRedirects( false );
        if (xmlMsg != null && xmlMsg.length() > 0)
            conn.setRequestMethod("POST");
        conn.setDoInput (true);
        conn.setDoOutput(true);

        String encoding = null;
        if (sensorUsername.length() != 0) {
            String userPassword = sensorUsername + ":" + sensorPassword;
            if (verbose)
                System.out.println("userpassword [" +userPassword+ "]");
            encoding = new sun.misc.BASE64Encoder().encode(userPassword.getBytes());
            conn.setRequestProperty ("Authorization", "Basic " + encoding);
        }

        conn.setRequestProperty( "Accept", "text/xml");
        conn.setRequestProperty( "Content-type", "xml/txt");
        conn.setRequestProperty( "Accept-Charset", "iso-8859-1,*,utf-8");
        conn.setRequestProperty( "User-Agent", "CIDS Client/4.0");
        conn.setRequestProperty( "Pragma", "no-cache");
        if (verbose) {
            System.out.println("Header request lines");
            System.out.println("   key [Accept]");
            System.out.println("      value [text/xml]");
            System.out.println("   key [Content-type]");
            System.out.println("      value [xml/txt]");
            System.out.println("   key [Accept-Charset]");
            System.out.println("      value [iso-8859-1,*,utf-8]");
            System.out.println("   key [User-Agent]");
            System.out.println("      value [CIDS Client/4.0]");
            System.out.println("   key [Pragma]");
            System.out.println("      value [no-cache]");
            if (sensorUsername.length() != 0) {
                System.out.println("   key [Authorization]");
                System.out.println("      value [" +encoding+ "]");
            }
        }

        return conn;
    }


    public static void usage () {
        System.out.println("Events v1.3   8 July, 2005");
        System.out.println("Usage:");
        System.out.println("   java EventCatcher sensorURL -u user/passwd [-o open params] [-g get params] [-v] ");
        System.out.println("    -u sensor username and password, separated by the / char");
        System.out.println("    -o The URI parameters included in the Open Subscription request.");
        System.out.println("       Open params: force (5.0 only), startTime, events, alertSeverities,");
        System.out.println("          errorSeverities, mustHaveAlarmTraits, mustNotHaveAlarmTraits.");
        System.out.println("       Force: yes, no");
        System.out.println("       Events: evStatus, evShunRqst, evError, evLogTransaction (4.x only), ");
        System.out.println("          evAlert (4.x only), evIdsAlert (5.0 only). ");
        System.out.println("          Concatenate multiple event types with the + char.");
        System.out.println("       AlertSeverities: informational, low, medium, high.");
        System.out.println("       ErrorSeverities: debug, warning, error, fatal.");
        System.out.println("    -g The URI parameters included in the Get Subscription request.");
        System.out.println("       Get params: timeout, maxNbrOfEvents, confirm.");
        System.out.println("    -v Verbose for additional messages.");
        System.out.println("   EventCatcher.java establishes an event subscription to 4.x and 5.0 sensors, ");
        System.out.println("   using sessionCookies.");
        System.out.println("   Press control-C to exit.");
        System.out.println("Example: get error events starting at the current time from a 5.0 sensor");
        System.out.println("   java EventCatcher https://192.168.1.1/cgi-bin/sdee-server -u cisco/password ");
        System.out.println("   -o \"force=yes&events=evError\" -g timeout=10");
        System.out.println("Example: get all events from a 4.x sensor");
        System.out.println("   java EventCatcher https://192.168.1.2/cgi-bin/event-server -u cisco/password ");
        System.out.println("   -o startTime=0 -g timeout=10");
        
    }

    /****************************** MAIN *****************************/

    /**
    * Main Function
    * For use when executing from the command line
    * @param args A list of arguments
    */
    public static void main (String[] args)
    {
        // Get the parms

        // uri is required
        if (args.length < 2) {
            usage();
            return;
        }

        boolean verbose = false;
        String sessionCookie = new String();
        String user = new String();
        String password = new String();

        String openParams = new String();
        String getParams = new String();
        
        int acount = args.length - 1;
        int i = 0;
        while (i < acount) {
            if ("-u".equals(args[1+i+0])) {
                if ((i+1) < acount)  {
                    String userPass = new String(args[1+i+1]);
                    String [] sbuf = userPass.split("/");
                    if (sbuf.length > 0)
                        user = sbuf[0];
                    if (sbuf.length > 1)
                        password = sbuf[1];
                    if (sbuf.length > 2) {
                        usage();
                        return;
                    }
                    i += 2;
                } else {
                    System.out.println("too few params for user/password");
                    usage();
                    return;
                }
            } else if ("-o".equals(args[1+i+0])) {
                if ((i+1) < acount)  {
                    openParams = new String(args[1+i+1]);
                    i += 2;
                } else {
                    System.out.println("too few open params");
                    usage();
                    return;
                }
            } else if ("-g".equals(args[1+i+0])) {
                if ((i+1) < acount)  {
                    getParams = new String(args[1+i+1]);
                    i += 2;
                } else {
                    System.out.println("too few get params");
                    usage();
                    return;
                }
            } else if ("-v".equals(args[1+i+0])) {
                verbose = true;
                ++i;
            } else {
                System.out.println("Unexpected parameter [" +args[1+i+0]+ "]");
                usage();
                return;
            }
        }
        // make sure either a user or a cookie is specified
        if (user.length() == 0 && sessionCookie.length() == 0) {
            usage();
            return;
        }

        String uri = args[0];
        // a common problem is to forget to specify /cgi-bin/servername
        if (uri.indexOf("/cgi-bin/") == -1) {
            System.out.println("The sensorURL parameter appears to be wrong [" +uri+ "]");
            System.out.println("Did you remember to specify '/cgi-bin/(eventServer)' ?");
            // return;
        }


        System.err.println("Press control-C to exit");
        EventCatcher ev = new EventCatcher(uri, user, password, verbose, openParams, getParams);
        ev.processEvents();

    }

}


//  **************  MYX509 TRUST MANAGER   ***************

/**
* This class performs trivial certificate checking - all certificates are accepted
*/
class MyX509TrustManager implements X509TrustManager
{
    /**
    * Trust all clients
    * @param chain the ceritficates to check
    * @param str the response
    */
    public void checkClientTrusted (X509Certificate[] chain, String str)
    {
    }

    /**
    * trust all servers
    * @param chain the ceritficates to check
    * @param str the response
    */
    public void checkServerTrusted (X509Certificate[] chain, String str)
    {
    }

    /**
    * there are no accepted issuers
    * @return null
    */
    public java.security.cert.X509Certificate[] getAcceptedIssuers ()
    {
        return null;
    }
}

//  **************  MYHOSTNAME VERIFIER ***************

/**
* This class performs trivial host name verification - all host names are accepted
*/
class  MyHostnameVerifier implements HostnameVerifier
{
    /**
    * trust all host names
    * @param urlHostname the host name to check
    * @param session the SSL session
    * @return always returns true
    */
    public boolean verify (String urlHostname, SSLSession session)
    {
        return true;
    }
}





