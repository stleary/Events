

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
 * limitations under the License. 
 * 
 *------------------------------------------------------------------
 */

import java.net.*;
import java.io.*;
import java.util.*;
import java.security.cert.*;

import javax.net.ssl.*;

import org.json.*;



/**
 * EventCatcher opens a subscription for events on a Cisco CX or v4-v7 IPS sensor
 * Simple build instructions:
 *  Minimum JDK: Java 1.8
 * 	Requires the JSON parsing package from www.org.json (https://github.com/douglascrockford/JSON-java)
 *  Here is a simple way to build and execute EventCatcher:
 * 	    cd to the directory of your choice
 *      copy EventCatcher.java to this directory
 *      Create an org/json subdirectory tree
 *      Pull the JSON-java files and copy them to org/json
 *      javac org/json/*java
 *      jar cvf JSON-java.jar org/json/*class
 *      javac EventCatcher.java
 *      java EventCatcher
 */

public class EventCatcher
{
	private static final String FOR_HELP_TYPE_JAVA_EVENT_CATCHER = "For help, type \"java EventCatcher\"";

	/**
	 * Lists all supported sensor types
	 * IPS means v5 or greater
	 * IPS v3 or less is not supported
	 */
	enum SensorType {
		IPS_V4("ipsv4"), IPS("ips"), CX("cx");
		private String sensor;
		SensorType(String s) {
			sensor = s;
		}
		public String toString() {
			return sensor;
		}
	};

	// specifies which type of sensor is being contacted
	SensorType sensorType;
	
    // Using the -v  parameter sets verbose=true for debug-level output
    boolean verbose = false;

    // sensor uri, the part which is common to all commands
    StringBuffer uri;
    
    // POST request xml content data
    StringBuffer sensorXmlMsg;

    // sensor username
    StringBuffer sensorUsername;

    // sensor password
    StringBuffer sensorPassword;

    // Session cookie returned by the server
    StringBuffer sessionCookie = new StringBuffer();

    // Subscription id returned by the sensor
    String subscriptionId = new String();

    /**
     * IPS sensor additional parameters
     */
    String openParams = new String();
    String getParams = new String();

    // installs the certification and hostname verification objects
    static
    {
        // create and install a trust manager that accepts all certs
        X509TrustManager tm = new MyX509TrustManager();
        TrustManager[] trustAllCerts = {tm};
        try {
            SSLContext sc = SSLContext.getInstance( "TLS" );
            sc.init( null, trustAllCerts, new java.security.SecureRandom() );
            HttpsURLConnection.setDefaultSSLSocketFactory( sc.getSocketFactory() );
        }   catch ( Exception e ) { }
        // create and install a host name verifier that accepts all hosts
        HostnameVerifier hv = new MyHostnameVerifier();
        try {
            HttpsURLConnection.setDefaultHostnameVerifier( hv );
        }   catch ( Exception e ) { }
    }

    /**
     * creates an EventCatcher with all values needed to subscribe for events
     * @param sensor sensor device type
     * @param uri common part of the uri for all requests
     * @param sensorUsername sensor username
     * @param sensorPassword sensor password
     * @param verbose enable debug messages
     * @param openParams IPS sensor open request params
     * @param getParams IPS sensor get request params
     */
    public EventCatcher (String sensor, String uri, String sensorUsername, String sensorPassword, boolean verbose,    
    		String openParams, String getParams)
    {
    	if (sensor.equals("ipsv4")) {
    		sensorType = SensorType.IPS_V4;
    	} else if (sensor.equals("ips")) {
    		sensorType = SensorType.IPS;
    	} else {
    		sensorType = SensorType.CX;
    	}
        this.uri = new StringBuffer(uri);
        this.sensorUsername = new StringBuffer(sensorUsername);
        this.sensorPassword = new StringBuffer(sensorPassword);
        this.verbose = verbose;
        this.openParams = openParams;
        this.getParams = getParams;
        sensorXmlMsg = new StringBuffer();
    }

    /**
     * processes events from the server, depending on the device type
     * Supported devices: 
     * 	IPS v4 
     * 	IPS v5 and greater
     *  CX  all versions
     */
    public void processEvents() {
    	if (isIPS()) {
        	// Different sensor versions connect to different servlets
        	if (sensorType == SensorType.IPS_V4) {
        		uri.append("/cgi-bin/event-server");
        	} else {
        		uri.append("/cgi-bin/sdee-server");
        	}
    		processIPSEvents();
    	} else {
    		processCXEvents();
    	}
    }

	/**
     * Gets CX events. It sends an unending sequence of event requests, 
     * starting with an action=open request.
     */
    private void processCXEvents() {
    	
    	/**
    	 * Login to device
    	 */
        StringBuffer authenticationUri= new StringBuffer(uri+"/authentication/login/");
        sensorXmlMsg = new StringBuffer("username="+sensorUsername+"&password="+sensorPassword+"&next=\"\"");
        StringBuffer str = new StringBuffer();
        boolean ok = processSensorRequest(authenticationUri.toString(), str);
        if (!ok) {
        	System.out.println("Failed to authenticate");
        	return;
        }
		
		/**
		 * Register an event subscription and get the subscription id
		 */
		StringBuffer subscriptionUri = new StringBuffer(uri+"/api/analyze/events/Eventrealtime/register.json");
		sensorXmlMsg = new StringBuffer("filter:{\"items\":[{\"include\":[\"true\"],"+
				"\"type\":[\"range\"],}\"name\":[\"Ev_TypeId\"],"+
				"\"value\":[\"0-2147483647\",\"30064771072-32212254719\",\"68719476736-70866960383\"]}],"+
				"\"op\":\"ALL\"}");
		ok = processSensorRequest(subscriptionUri.toString(), str);
        if (!ok) {
        	System.out.println("Failed to register");
        	return;
        }
        
        /**
         * Registration actually returns a malformed json object.
         * There are 2 concatenated objects without a comma,
         * enclosing square brackets, or array name. 
         * The first object is defective too. Just grab the 2nd one
         */
        int idx = str.toString().indexOf("}{");
        if (idx != -1) {
        	str = new StringBuffer(str.substring(idx+1));
        }
    	JSONObject json = new JSONObject(str.toString());
   		Boolean isValid = json.getBoolean("valid");
   		if (isValid) {
   			subscriptionId = json.getString("id");
   		} else {
   			System.out.println("regId part of registration response not valid");
    		return;
    	}

        // now get some events!
		StringBuffer getUri = new StringBuffer(uri+"/api/analyze/events/Eventrealtime/rtdata/" +subscriptionId+ ".json?tz=360&rows=25");
        while (ok) {
            str = new StringBuffer();
            ok = processSensorRequest(getUri.toString(), str);

            boolean eventsFound = true;
            json = new JSONObject(str.toString());
            isValid = json.getBoolean("valid");
            if (!isValid) {
            	System.out.println("rtdata response was not valid: " +str.toString());
            	return;
            }
            Integer rows = json.getInt("numRows");
            if (rows == 0) {
            	eventsFound = false;
            }
            if (eventsFound) {
                JSONArray items = json.getJSONArray("items");
                String s = items.toString(3);
                System.out.println(s);
            }
            try {
                Thread.sleep(1000);
            } catch (Exception e) {}
        }
	}

	/**
    * Gets IPS events. It sends an unending sequence of event requests, 
    * starting with an action=open request.
    */
    private void processIPSEvents()
    {
    	/**
    	 * Set open params and open a connection to the sensor
    	 */
        StringBuffer openUri = new StringBuffer(uri+"?action=open&sessionCookies=yes");
        if (openParams.length() > 0) {
            openUri.append(new StringBuffer("&"));
            openUri.append(new StringBuffer(openParams));
        }
        StringBuffer str = new StringBuffer();
        boolean ok = processSensorRequest(openUri.toString(), str);

        // action=get params
        StringBuffer getUri = new StringBuffer(uri+"?action=get");
        if (getParams.length() > 0) {
            getUri.append(new StringBuffer("&"));
            getUri.append(new StringBuffer(getParams));
        }
        if (isIPS() && subscriptionId.length() > 0) {
            getUri.append(new StringBuffer("&subscriptionId="));
            getUri.append(new StringBuffer(subscriptionId));
        }

        // get events loop
        while (ok) {
            str = new StringBuffer();
            ok = processSensorRequest(getUri.toString(), str);
            boolean eventsFound = true;
            // 5.0 check
            if (sensorType == SensorType.IPS && 
            		str.toString().indexOf("<sd:events></sd:events>") != -1) {
                eventsFound = false;
            // 4.x check
            } else if (sensorType == SensorType.IPS_V4 &&
            		str.toString().indexOf("schemaVersion=\"1.00\"></events>") != -1) {
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
    * Process a sensor request and store the response
    * @param requestUri the uri to use for this request
    * @param responseStringBuffer will contain the response text
    * @return true if successful, otherwise false 
    */
    private boolean processSensorRequest (String requestUri, StringBuffer responseStringBuffer)
    {
        try {
            if (verbose) {
                System.out.println("\nRequest URI [" +uri+ "]\n");
            }
            
            InputStream is = dispatchSensorMessage(requestUri, sensorXmlMsg.toString());
            InputStreamReader in =  new InputStreamReader(is);
            BufferedReader reader = new BufferedReader(in);
            String line = null;
            while((line = reader.readLine()) != null) {
                responseStringBuffer.append(line);
            }
            if (verbose) {
            	if (sessionCookie.length() > 0) {
            		System.out.println("SessionCookie [" +sessionCookie+ "]\n");
            	}
                System.out.println("Response [" +responseStringBuffer+ "]");
            }

            // check for useful response info
            String sid = new String ("<sd:subscriptionId>");
            int indx = responseStringBuffer.toString().indexOf(sid);
            if (indx != -1) {
                int indx1 = indx + sid.toString().length();
                int indx2 = responseStringBuffer.toString().indexOf('<', indx1);
                if (verbose) {
                    System.out.println("indx1 [" +indx1+ "] indx2 [" +indx2+ "]");
                }
                subscriptionId = responseStringBuffer.toString().substring(indx1, indx2);
                if (verbose) {
                    System.out.println("subscriptionId [" +subscriptionId+ "]");
                }

            }
            return true;
        }
        catch (Exception e) {
            System.out.println("Error when sending message to sensor [" +e.getMessage()+ "]");
            return false;
        }
    }

   /**
    * Dispatch a message to the sensor and opens a reader on the response
    * @param uri the complete URI string
    * @param xmlMsg contains the XML request data.
    * @param responseParameters output, contains the HTTP header parameter pairs.
    * @return The input stream for the response
    * @throws Exception
    */
    private InputStream dispatchSensorMessage (String uri, String xmlMsg) throws Exception
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
            if (verbose) {
                System.out.println("response params found [" +params+ "]");
            }
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
                if (verbose) {
                    System.out.println("= index [" +index+ "] + index [" +
                    		index1+ "] key [" +key+ "] value [" +value+ "]");
                }
                if ("subscriptionId".equals(key)) {
                    if (verbose) {
                        System.out.println("subscriptionId [" +value+ "]");
                    }
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
            Map<String, List<String>> map = httpConn.getHeaderFields();
            if (map != null) {
                Set<String> keySet = map.keySet();
                if (keySet != null) {
                    Iterator<String> it = keySet.iterator();
                    while (it.hasNext()) {
                        String key = it.next();
                        System.out.println("   key [" +key+ "]");
                        List<String> list = map.get(key);
                        if (list != null) {
                            Iterator<String> it1 = list.iterator();
                            while (it1.hasNext()) {
                                String value = it1.next();
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
    * Builds a http header for a sensor request
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
        HttpURLConnection.setFollowRedirects( false );
        if (xmlMsg != null && xmlMsg.length() > 0)
            conn.setRequestMethod("POST");
        conn.setDoInput (true);
        conn.setDoOutput(true);

        String encoding = null;
        if (isIPS() && sensorUsername.length() != 0) {
            String userPassword = sensorUsername + ":" + sensorPassword;
            if (verbose) {
                System.out.println("userpassword [" +userPassword+ "]");
            }
        	char[] chArray = Base64Coder.encode (userPassword.getBytes(), 0, userPassword.length());
        	encoding = new String(chArray);
            conn.setRequestProperty ("Authorization", "Basic " + encoding);
        }

        conn.setRequestProperty( "Accept", "text/xml");
        conn.setRequestProperty( "Content-type", "xml/txt");
        conn.setRequestProperty( "Accept-Charset", "iso-8859-1,*,utf-8");
        conn.setRequestProperty( "User-Agent", "CIDS Client/4.0");
        conn.setRequestProperty( "Pragma", "no-cache");
        String xmlStr = "XMLHttpRequest";
        String contentTypeStr = "application/x-www-form-urlencoded";
        if (!isIPS()) {
        	conn.setRequestProperty("X-Requested-With", xmlStr);
        	conn.setRequestProperty("Content-Type", contentTypeStr);
        }
        if (verbose) {
        	// TODO: just get the data from conn 
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
            if (isIPS() && sensorUsername.length() != 0) {
                System.out.println("   key [Authorization]");
                System.out.println("      value [" +encoding+ "]");
            }
            if (!isIPS()) {
            	System.out.println("   key[X-Requested-With]");
            	System.out.println("      value["+xmlStr+"]");
            	System.out.println("   key[Content-Type]");
            	System.out.println("      value["+contentTypeStr+"]");
            }
        }

        return conn;
    }


    public static void usage () {
        System.out.println("EventCatcher v2.0   11 Mar, 2015");
        System.out.println("Usage:");
        System.out.println("   Events sensorURL -u user/passwd [-d deviceType] [-o open params] [-g get params] [-v] ");
        System.out.println("    -u sensor username and password, separated by the / char");
        System.out.println("    -d device type: ipsv4, ips, cx. By default CX will be selected");
        System.out.println("    -o The URI parameters included in the Open Subscription request.");
        System.out.println("       Open params: force (5.0 only), startTime, events, alertSeverities,");
        System.out.println("          errorSeverities, ustHaveAlarmTraits, mustNotHaveAlarmTraits.");
        System.out.println("       Force: yes, no");
        System.out.println("       Events: evStatus, evShunRqst, evError, evLogTransaction (4.x only), ");
        System.out.println("          evAlert (4.x only), evIdsAlert (5.0 only). ");
        System.out.println("          Concatenate multiple event types with the+ char.");
        System.out.println("       AlertSeverities: informational, low, medium,high.");
        System.out.println("       ErrorSeverities: debug, warning, error, fatal.");
        System.out.println("    -g The URI parameters included in the Get Subscription request.");
        System.out.println("       Get params: timeout, maxNbrOfEvents, confirm.");
        System.out.println("    -v Verbose for additional messages.");
        System.out.println("   EventCatcher establishes an event subscription to a Cisco sensor and retrieves events.");
        System.out.println("   Press control-C to exit.");
        System.out.println("Example: get error events starting at the current time from a 5.0 sensor");
        System.out.println("   java EventCatcher  https://192.168.1.1 -u cisco/password -d ips");
        System.out.println("   -o \"force=yes&events=evError\" -g timeout=10");
        System.out.println("Example: get all events from a 4.x sensor");
        System.out.println("   java EventCatcher https://192.168.1.2 -u cisco/password -d ipsv4");
        System.out.println("   -o startTime=0 -g timeout=10");
        System.out.println("Example: get all events from a CX sensor");
        System.out.println("   java EventCatcher https://192.168.1.2 -u cisco/password");

    }

    /**
    * Main entry point
    * @param args A list of command line parameters
    */
    public static void main (String[] args)
    {
        // uri is required
        if (args.length < 2) {
            usage();
            return;
        }

        boolean verbose = false;
        String sessionCookie = new String();
        String user = new String();
        String password = new String();
        String sensor = new String("cx");

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
                    	System.out.println("Too many user/password parameters");
                        System.out.println(FOR_HELP_TYPE_JAVA_EVENT_CATCHER);
                        return;
                    }
                    i += 2;
                } else {
                    System.out.println("too few params for user/password");
                    System.out.println(FOR_HELP_TYPE_JAVA_EVENT_CATCHER);
                    return;
                }
            } else if ("-o".equals(args[1+i+0])) {
                if ((i+1) < acount)  {
                    openParams = new String(args[1+i+1]);
                    i += 2;
                } else {
                    System.out.println("too few open params");
                    System.out.println(FOR_HELP_TYPE_JAVA_EVENT_CATCHER);
                    return;
                }
            } else if ("-g".equals(args[1+i+0])) {
                if ((i+1) < acount)  {
                    getParams = new String(args[1+i+1]);
                    i += 2;
                } else {
                    System.out.println("too few get params");
                    System.out.println(FOR_HELP_TYPE_JAVA_EVENT_CATCHER);
                    return;
                }
            } else if ("-d".equals(args[1+i+0])) {
                if ((i+1) < acount)  {
                    sensor = new String(args[1+i+1]).toLowerCase();
                    i += 2;
                    if (!(sensor.equals("ipsv4") ||
                    		sensor.equals("ips") ||
                    		sensor.equals("cx"))) {
                    	System.out.println("invalid device type");
                        System.out.println(FOR_HELP_TYPE_JAVA_EVENT_CATCHER);
                        return;
                    }
                } else {
                    System.out.println("too few device params");
                    System.out.println(FOR_HELP_TYPE_JAVA_EVENT_CATCHER);
                    return;
                }
            } else if ("-v".equals(args[1+i+0])) {
                verbose = true;
                ++i;
            } else {
                System.out.println("Unexpected parameter [" +args[1+i+0]+ "]");
                System.out.println(FOR_HELP_TYPE_JAVA_EVENT_CATCHER);
                return;
            }
        }
        // make sure either a user or a cookie is specified
        if (user.length() == 0 && sessionCookie.length() == 0) {
            usage();
            return;
        }

        // input params ok, start the EventCatcher
        String uri = args[0];
        System.err.println("Press control-C to exit");
        EventCatcher ev = new EventCatcher(sensor, uri, user, password, verbose, openParams, getParams);
        ev.processEvents();

    }
    
    /**
     * @return true for v4+ ips, otherwise false
     */
    private boolean isIPS() {
    	return (sensorType == SensorType.IPS || sensorType == SensorType.IPS_V4);
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

//Copyright 2003-2010 Christian d'Heureuse, Inventec Informatik AG, Zurich, Switzerland
//www.source-code.biz, www.inventec.ch/chdh
//
//This module is multi-licensed and may be used under the terms
//of any of the following licenses:
//
//EPL, Eclipse Public License, V1.0 or later, http://www.eclipse.org/legal
//LGPL, GNU Lesser General Public License, V2.1 or later, http://www.gnu.org/licenses/lgpl.html
//GPL, GNU General Public License, V2 or later, http://www.gnu.org/licenses/gpl.html
//AGPL, GNU Affero General Public License V3 or later, http://www.gnu.org/licenses/agpl.html
//AL, Apache License, V2.0 or later, http://www.apache.org/licenses
//BSD, BSD License, http://www.opensource.org/licenses/bsd-license.php
//MIT, MIT License, http://www.opensource.org/licenses/MIT
//
//Please contact the author if you need another license.
//This module is provided "as is", without warranties of any kind.
//
//Project home page: www.source-code.biz/base64coder/java


/**
* A Base64 encoder/decoder.
*
* <p>
* This class is used to encode and decode data in Base64 format as described in RFC 1521.
*
* @author
*    Christian d'Heureuse, Inventec Informatik AG, Zurich, Switzerland, www.source-code.biz
*/
class Base64Coder {

	//The line separator string of the operating system.
	private static final String systemLineSeparator = System.getProperty("line.separator");

	//Mapping table from 6-bit nibbles to Base64 characters.
	private static final char[] map1 = new char[64];
	static {
		int i=0;
		for (char c='A'; c<='Z'; c++) map1[i++] = c;
		for (char c='a'; c<='z'; c++) map1[i++] = c;
		for (char c='0'; c<='9'; c++) map1[i++] = c;
		map1[i++] = '+'; map1[i++] = '/'; }

	//Mapping table from Base64 characters to 6-bit nibbles.
	private static final byte[] map2 = new byte[128];
	static {
		for (int i=0; i<map2.length; i++) map2[i] = -1;
		for (int i=0; i<64; i++) map2[map1[i]] = (byte)i; }

	/**
	 * Encodes a string into Base64 format.
	 * No blanks or line breaks are inserted.
	 * @param s  A String to be encoded.
	 * @return   A String containing the Base64 encoded data.
	 */
	public static String encodeString (String s) {
		return new String(encode(s.getBytes())); }

	/**
	 * Encodes a byte array into Base 64 format and breaks the output into lines of 76 characters.
	 * This method is compatible with <code>sun.misc.BASE64Encoder.encodeBuffer(byte[])</code>.
	 * @param in  An array containing the data bytes to be encoded.
	 * @return    A String containing the Base64 encoded data, broken into lines.
	 */
	public static String encodeLines (byte[] in) {
		return encodeLines(in, 0, in.length, 76, systemLineSeparator); }

	/**
	 * Encodes a byte array into Base 64 format and breaks the output into lines.
	 * @param in            An array containing the data bytes to be encoded.
	 * @param iOff          Offset of the first byte in <code>in</code> to be processed.
	 * @param iLen          Number of bytes to be processed in <code>in</code>, starting at <code>iOff</code>.
	 * @param lineLen       Line length for the output data. Should be a multiple of 4.
	 * @param lineSeparator The line separator to be used to separate the output lines.
	 * @return              A String containing the Base64 encoded data, broken into lines.
	 */
	public static String encodeLines (byte[] in, int iOff, int iLen, int lineLen, String lineSeparator) {
		int blockLen = (lineLen*3) / 4;
		if (blockLen <= 0) throw new IllegalArgumentException();
		int lines = (iLen+blockLen-1) / blockLen;
		int bufLen = ((iLen+2)/3)*4 + lines*lineSeparator.length();
		StringBuilder buf = new StringBuilder(bufLen);
		int ip = 0;
		while (ip < iLen) {
			int l = Math.min(iLen-ip, blockLen);
			buf.append(encode(in, iOff+ip, l));
			buf.append(lineSeparator);
			ip += l; }
		return buf.toString(); }

	/**
	 * Encodes a byte array into Base64 format.
	 * No blanks or line breaks are inserted in the output.
	 * @param in  An array containing the data bytes to be encoded.
	 * @return    A character array containing the Base64 encoded data.
	 */
	public static char[] encode (byte[] in) {
		return encode(in, 0, in.length); }

	/**
	 * Encodes a byte array into Base64 format.
	 * No blanks or line breaks are inserted in the output.
	 * @param in    An array containing the data bytes to be encoded.
	 * @param iLen  Number of bytes to process in <code>in</code>.
	 * @return      A character array containing the Base64 encoded data.
	 */
	public static char[] encode (byte[] in, int iLen) {
		return encode(in, 0, iLen); }

	/**
	 * Encodes a byte array into Base64 format.
	 * No blanks or line breaks are inserted in the output.
	 * @param in    An array containing the data bytes to be encoded.
	 * @param iOff  Offset of the first byte in <code>in</code> to be processed.
	 * @param iLen  Number of bytes to process in <code>in</code>, starting at <code>iOff</code>.
	 * @return      A character array containing the Base64 encoded data.
	 */
	public static char[] encode (byte[] in, int iOff, int iLen) {
		int oDataLen = (iLen*4+2)/3;       // output length without padding
		int oLen = ((iLen+2)/3)*4;         // output length including padding
		char[] out = new char[oLen];
		int ip = iOff;
		int iEnd = iOff + iLen;
		int op = 0;
		while (ip < iEnd) {
			int i0 = in[ip++] & 0xff;
			int i1 = ip < iEnd ? in[ip++] & 0xff : 0;
			int i2 = ip < iEnd ? in[ip++] & 0xff : 0;
			int o0 = i0 >>> 2;
			int o1 = ((i0 &   3) << 4) | (i1 >>> 4);
			int o2 = ((i1 & 0xf) << 2) | (i2 >>> 6);
			int o3 = i2 & 0x3F;
			out[op++] = map1[o0];
			out[op++] = map1[o1];
			out[op] = op < oDataLen ? map1[o2] : '='; op++;
			out[op] = op < oDataLen ? map1[o3] : '='; op++; }
		return out; }

	//Dummy constructor.
	private Base64Coder() {}

}
