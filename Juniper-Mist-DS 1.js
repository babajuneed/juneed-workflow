import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import com.santaba.agent.util.Settings
import java.util.Random
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import groovy.transform.Field
import java.util.Date
import java.text.SimpleDateFormat
import java.net.URLEncoder
import org.apache.http.HttpEntity
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.client.methods.HttpGet
import org.apache.http.client.methods.HttpPost
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.apache.http.util.EntityUtils
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.codec.binary.Hex
import org.apache.http.entity.ContentType
import org.apache.http.entity.StringEntity

debug = true

oauthAccessToken = null
slurper = new JsonSlurper()

def props = [
    host     : hostProps.get("system.hostname"),
    user     : hostProps.get("juniper.user"),
    pass     : hostProps.get("juniper.pass"),
	org_id     : hostProps.get("juniper.org.id"),
    collplat : hostProps.get("system.collectorplatform")
]

LMDebugPrint("""Properties set -
    Host:  ${props.host}
    User:  ${props.user}
	Pass:  ${props.pass}
	Org_id:  ${props.org_id}
    Collector Platform:  ${props.collplat}
    """, debug)

if (proxyInfo.enabled) {
    LMDebugPrint("""Proxy enabled -
    Host:  ${proxyInfo.host}
    Port:  ${proxyInfo.port}
	User:  ${proxyInfo.user}
	Pass:  ${proxyInfo.pass}
    """, debug)
}

def success = false


// Retrieve cached session ID and CSRF token
//creds = new ConcurrentHashMap()
//creds = getCachedSession(props, proxyInfo)

// Retrieve token
response = generateOauthToken(props, proxyInfo)
LMDebugPrint("response = ${response}", debug)
oauthAccessToken = "Bearer ${response.key}"
LMDebugPrint("${oauthAccessToken}", debug)


def LMDebugPrint(message, debug=false) {
    if (debug) {
        println(message.toString())
    }
}


def generateOauthToken(props, proxyInfo) {
    def oauthUrl = "https://api.ac2.mist.com/api/v1/self/apitokens"
    LMDebugPrint("\nTrying to fetch data from ${oauthUrl} ...", debug)
    // Set headers based on whether we can use CSRF token



    def responseBody
    def responseCode
    def exception // Capture exception because response code returned is falsely 200



    try {
        //def url = "${oauthUrl}".toURL()
        URL url = new URL(oauthUrl)
		LMDebugPrint("url:${url}", debug)
        HttpURLConnection conn = null



        def creds = "${props.user}:${props.pass}"
		LMDebugPrint("creds:${creds}", debug)
        def encodedCreds = Base64.getEncoder().encodeToString(creds.getBytes())



        if (proxyInfo.enabled) {
            LMDebugPrint("\tAttempting with proxy...",debug)
            conn = (HttpURLConnection) url.openConnection(proxyInfo.proxy)
        }
        else {
            conn = (HttpURLConnection) url.openConnection()
        }



        String urlParameters  = "username=${props.user} && password=${props.pass}";



        //byte[] postData = urlParameters.getBytes( StandardCharsets.UTF_8 );
        byte[] postData = urlParameters.getBytes();
        int postDataLength = postData.length;




        conn.setDoOutput(true);
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("POST")




        //conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
		conn.setRequestProperty("Content-Type", "application/json");
		conn.setRequestProperty("Accept", "application/json");



        String userpass = "${props.user}:${props.pass}";
        String basicAuth = "Basic " + javax.xml.bind.DatatypeConverter.printBase64Binary(userpass.getBytes());
		

        conn.setRequestProperty ("Authorization", basicAuth);
		




        conn.setUseCaches(false);
        DataOutputStream wr = new DataOutputStream(conn.getOutputStream())
		LMDebugPrint("conn.. = ${conn}",debug)
        //wr.write( postData );
        //InputStream in = conn.getInputStream();
        conn.connect()
        responseCode = conn.getResponseCode()
        responseBody = conn.getInputStream().getText()
		LMDebugPrint("responseBody = ${responseBody}",debug)
        def jsonResponse = slurper.parseText(responseBody)
        LMDebugPrint("jsonResponse = ${jsonResponse}",debug)

        println(responseCode)
        println(responseBody)



        if (responseCode == 200 && !responseBody.contains("html")) { // Failure typically has 200 status code and a returned html page
            LMDebugPrint("\tSUCCESS!",debug)
            LMDebugPrint("Raw output:\n\t${responseBody}\n\n")



            //def jsonResponse = slurper.parseText(responseBody)
            //return jsonResponse
        }
    }



    catch (Exception e) {
        exception = e
        LMDebugPrint("\tException occurred:\t${e}",debug)
    }



    // If the session is stale or there was some other auth issue, then delete cache the file, logout session, relogin, then try again
    if ( (responseCode == 200 && responseBody?.contains("html")) || exception?.toString().contains("403")) {
        LMDebugPrint("\tAuth failed. Got login page...\n\tStale session token or other auth failure occurred. STATUS CODE: ${responseCode}",debug)



        // If we've already failed, then it must not be an auth issue
    }
    if (exception?.toString().contains("500")) {
        LMDebugPrint("\tInternal server error. Retrying. STATUS CODE: ${responseCode}")
    }
    LMDebugPrint("\tCould not fetch data from ${oauthUrl}",debug)



    return null
    //return jsonResponse




}

def getProxyInfo() {
    def collectorProxy = Settings.getSetting("proxy.enable").toBoolean()
    Map proxyInfo = [:]

    if (collectorProxy) {
        proxyInfo = [
            enabled   : true,
            host : Settings.getSetting("proxy.host"),
            user : Settings.getSetting("proxy.user"),
            pass : Settings.getSetting("proxy.pass")
        ]

        proxyInfo["proxy"] = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyInfo.host, proxyInfo.port))
    }

    return proxyInfo
}



