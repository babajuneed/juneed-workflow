/*******************************************************************************
 * © 2007-2021 - LogicMonitor, Inc. All rights reserved.
 Author:Nagaraja Chikkabidri
 Note: Capture the Juniper Mist Alarms
 Date:21/06/2022
 Last Modified Date:28/06/2022

******************************************************************************/
import groovy.json.JsonSlurper
import groovy.json.JsonOutput
import com.santaba.agent.util.Settings
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

def props = [
    host     : hostProps.get("system.hostname"),
    hostDisplayName     : hostProps.get("system.displayname"),
    user     : hostProps.get("juniper.user"),
    pass     : hostProps.get("juniper.pass"),
    collplat : hostProps.get("system.collectorplatform"),
    orgID    : hostProps.get("juniper.org.id"),
    siteID   : hostProps.get("juniper.site.id"),
    lmAccount : Settings.getSetting("lmaccount"),
    lmAccessId : Settings.getSetting("lmaccess.id"),
    lmAccessKey : Settings.getSetting("lmaccess.key"),
    deviceId   : hostProps.get("system.deviceId")
]


// To run in debug mode, set to true
@Field def debug = false
@Field long startTime = System.currentTimeMillis()
@Field long end = startTime/1000;
//@Field long start = end - (60 * 60)
@Field long start = end - (90 * 24 * 60 * 60)
LMDebugPrint("start = ${start} and End = ${end}", debug)
// Container for recording API response times to reference if performance issues arise
apiCallTimes = []
LMDebugPrint("Orgid = ${props.orgID}\n SIteID = ${props.siteID}", debug)
LMDebugPrint("lmaccount ${props.lmAccount} and lmaccessid ${props.lmAccessId} deviceId is ${props.deviceId} hostDisplayName is ${props.hostDisplayName}", debug)

def proxyInfo = getProxyInfo()

LMDebugPrint("""Properties set -
    Host:  ${props.host}
    User:  ${props.user}
    Collector Platform:  ${props.collplat}
    Orgid:  ${props.orgID}
    siteID:  ${props.siteID}
    """, debug)

if (proxyInfo.enabled) {
    LMDebugPrint("""Proxy enabled -
    Host:  ${proxyInfo.host}
    Port:  ${proxyInfo.port}
    """, debug)
}

// Transform API severity to LM severity
@Field def severity = [
    "critical" : "critical",
    "warn" : "error",
    "info" : "warn",
    "Error" : "error",
    "Warning" : "warn",
]


// Setup the script cache and see if it can be used
@Field def useCache = true
@Field def cacheDedupTimeout = 60// Timeout in minutes for deduplication of errors. Set to 1 hours for now.
collectorCache = null

@Field def scriptCache

try 
{
    scriptCache = this.class.classLoader.loadClass("com.santaba.agent.util.script.ScriptCache").getCache()
    LMDebugPrint("Collector using script cache to prevent duplicate events.\n", debug)
    //useCache = false
}
catch (ClassNotFoundException ex) 
{
    LMDebugPrint("Collector version does not support script cache. Upgrade to 29.100 or higher for support.\nSee more info at https://www.logicmonitor.com/support/collectors/collector-configurations/collector-script-caching\n", debug)
    useCache = false
}

// LM has limitation that allows the creation of only 50 alerts at a time
@Field int maxAlaramsLM = 50
// hence we will create and cache 50 alarms first time and another 50 in next batch subsequently
@Field int alarmCounter = 0

// pull the Devices list from device datasource
@Field Map DS_devices = [:]

// get all the device from device datasource
Jun_Mist_DS = ["Juniper_Mist_AP", "Juniper_Mist_Gateway", "Juniper_Mist_Switch"]

for (mist_ds in Jun_Mist_DS) {
    LMDeviceDatasourceID = getLMDeviceDatasourceID(props,mist_ds)
    LMDebugPrint("LM Device Datasource ID for ${mist_ds} is ${LMDeviceDatasourceID}")
}
LMDebugPrint("DS_devices = ${DS_devices}", debug)

LMDebugPrint("Starting fetching Juniper-Mist alarms..!!!\n", debug)
def success = false
serviceUrl = "https://api.mist.com"

def baseUrl = "${serviceUrl}/api/v1/sites/${props.siteID}"
slurper = new JsonSlurper()

tokenResponse = generateOauthToken(props, proxyInfo)
LMDebugPrint("response = ${tokenResponse}", debug)
oauthAccessToken = "${tokenResponse.key}"
LMDebugPrint("${oauthAccessToken}", debug)
		
def page = "";
@Field def json = [:]
json["events"] = []


long apiCallStart = System.currentTimeMillis()
def response = httpGet(props, "alarms/search", baseUrl, page, start, end, proxyInfo, debug)
long apiCallEnd = System.currentTimeMillis()
def apiTotal = apiCallEnd - apiCallStart
apiCallTimes << apiTotal
LMDebugPrint("Total API call time for first call = ${apiTotal} \nstarttime = ${apiCallStart}\nend time = ${apiCallEnd}", debug)
LMDebugPrint("response size = ${response.size()}", debug)
LMDebugPrint("Page no: ${page}", debug)

extractAlarms(response)
page = response?.next ?: '';
LMDebugPrint("Page = ${page}", debug)
while(page)
{
  apiCallStart = System.currentTimeMillis()
  response = httpGet(props, "alarms/search", baseUrl, page, start, end, proxyInfo, debug)
  apiCallEnd = System.currentTimeMillis()
  apiTotal = apiCallEnd - apiCallStart
  apiCallTimes << apiTotal
  LMDebugPrint("Total API call time = ${apiTotal} \nstarttime = ${apiCallStart}\nend time = ${apiCallEnd}", debug)
  extractAlarms(response)
  page = response?.next ?: '';
  LMDebugPrint("Page = ${page}", debug)
}

if (json['events'].size > 0) 
{
  // Yes, convert the json map to a JSON string and print it pretty
  //println "inside json print"
  println JsonOutput.prettyPrint(JsonOutput.toJson(json))
  LMDebugPrint("alarms size = ${json['events'].size}", debug)
}

success = true


LMDebugPrint("API Call: ${apiCallTimes}", debug)
LMDebugPrint("\n\n*****\nAverage API call response time: ${apiCallTimes.sum() / apiCallTimes.size()}", debug)
LMDebugPrint("Total runtime: ${timer(startTime)}", debug)

return success ? 0 : 1



////////////////////////////////////////////////////////////////////////////////
//  METHODS
//////////////////////////////////////////////////////////////////////////////
/*
 * Helper function to print out debug messages for troubleshooting purposes
 */
def LMDebugPrint(message, debug=false) 
{
  if (debug) 
  {
     println(message.toString())
  }
}

//Alarms extract from Mist
def extractAlarms(response)
{
   response?.'results'.each 
   { alarms ->
     Map MistAlarms = [:]
     def severity = severity[alarms.'severity'] ?: "warn";
     def uniqueId = alarms.'id';
     def type  = alarms.'type';
     def group = alarms.'group';
     def reasons = alarms.'reasons' ?: "";
	 long alarmtime = alarms.'timestamp';

     // Convert date to a format LM can read properly
     Date dateRaw   = new Date(alarmtime * 1000)
     def formatDate = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZZ").format(dateRaw)
	 
     long startTime = System.currentTimeMillis()
     Date currentdate = new Date(startTime);
     def datetime = currentdate.format("yyyy-MM-dd'T'HH:mm:ss.SSSZZ").toString()	
	 
	// println "alarmtime = ${alarmtime} and formatDate = ${formatDate} and startTime = ${startTime} and datetime=${datetime}"
	 
     //def dedupSuppress = false
     def dedupSuppress = checkCache(uniqueId)
     if (!dedupSuppress) 
	 {

       for (hostnames in alarms.'hostnames' ) 
	   {
	        MistAlarms["severity"]   = severity
			MistAlarms["happenedOn"] = datetime
			//MistAlarms["happenedOn"] = formatDate
			MistAlarms["uniqueId"] = uniqueId
			MistAlarms["group"] = group
			MistAlarms["message"] = "Type = ${type}  -Affected Hosts=${alarms.'hostnames'} -  Reasons=${reasons}\n"
			MistAlarms["auto.affected_ci"] = hostnames
            affected_ci_sysId = DS_devices[hostnames+".sysId"]
			MistAlarms["auto.affected_ci_sysid"] = affected_ci_sysId
		}
       json["events"] << MistAlarms
	   if (scriptCache) 
	   {
          scriptCache.set("MistAlarms.${uniqueId}","1",cacheDedupTimeout * 60 * 1000)
          alarmCounter++
        }
       LMDebugPrint("Alarm Counter = ${alarmCounter}", debug)
       if(alarmCounter >= maxAlaramsLM) 
	   {
           LMDebugPrint("processed and cached ${alarmCounter} events...skipping remaining for next exec..", debug)
          //ask the invoking main loop to break processing of the vManage alarms
          return false
        }
     }
   }
}
/*
 * Helper function to time pieces of script for troubleshooting purposes
 */
def timer(startTime) 
{
    long endTime   = System.currentTimeMillis()
    long totalTime = endTime - startTime
    return totalTime
}

def checkCache(uniqueId) 
{
    // Check to see if this issue is in the script cache
    if (useCache && scriptCache.get("MistAlarms.${uniqueId}"))
	{
        LMDebugPrint("Skipping alarm ${uniqueId}, already reported", debug)
        //println "Skipping alarm ${uniqueId}, already reported";
        return true
    }
    return false
}

/*
 * Get collector proxy settings
 */
def getProxyInfo() {
    //def collectorProxy = hostProps.get("proxy.enable") ?: false
    def collectorProxy = false
    Map proxyInfo = [:]

    if (collectorProxy) {
        if (Settings.getSetting("proxy.enable").toBoolean()) {
            proxyInfo = [
                enabled   : true,
                host : Settings.getSetting("proxy.host"),
                port : Settings.getSetting("proxy.port")?.toInteger(),
                user : Settings.getSetting("proxy.user"),
                pass : Settings.getSetting("proxy.pass")
            ]

            proxyInfo["proxy"] = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyInfo.host, proxyInfo.port))
        }
    }

    return proxyInfo
}


/*
 *  Generic GET method for API calls
 */

def httpGet(props, endpoint, baseUrl, page, start, end, proxyInfo, debug, alreadyFailed=false) 
{
    LMDebugPrint("inside function and page = ${page} and endpoint=${endpoint} and serviceUrl = ${serviceUrl}", debug)
	def url = "";
    if (page == "")
    {
		//url = "${baseUrl}/${endpoint}?limit=100".toURL()
		url = "${baseUrl}/${endpoint}?start=${start}&end=${end}&limit=50".toURL()
    }
    else 
	{
		url = "${serviceUrl}${page}".toURL()
    }

    LMDebugPrint("\nTrying to fetch data from ${url} ...", debug)
    if (proxyInfo.enabled) 
	{
        LMDebugPrint("\tAttempting with proxy...", debug)
        conn = url.openConnection(proxyInfo.proxy)
    }
    else 
	{ 
		conn = url.openConnection() 
	}

    def responseBody
    def responseCode
    def exception // capture exception for unique
    try 
	{
        //def userCredentials = "${props.user}:${props.pass}"
        //def basicAuth = "Basic " + new String(Base64.getEncoder().encode(userCredentials.getBytes()))
		//conn.setRequestProperty("Authorization", basicAuth);
		conn.setRequestProperty("Authorization", oauthAccessToken);
        conn.setRequestMethod("GET")
        conn.setDoOutput(true)
        conn.setRequestProperty ("Accept", "application/json")
        conn.setRequestProperty ("Content-Type", "application/json")
        responseCode = conn.getResponseCode()
        responseBody = conn.getInputStream().getText()

        if (responseCode == 200 || (responseCode == 401 && !responseBody.contains("html")))  { // success indicated by 401 and no html in response?
            LMDebugPrint("\tSUCCESS!\nRaw output:\n\t${responseBody}\n\n", debug)
            //println JsonOutput.prettyPrint(responseBody)
            return slurper.parseText(responseBody)
        }

    }
    catch (Exception e) 
	{
        exception = e
        LMDebugPrint("\tException occurred getting endpoint /${endpoint}:\n${e}", debug)
    }

    // If the session is stale or there was some other auth issue, then delete cache the file, logout session, relogin, then try again
    if ( (responseCode == 200 && responseBody?.contains("html")) || exception?.toString().contains("403")  || exception?.toString().contains("401")) {
        LMDebugPrint("\tAuth failed. Got login page...\n\tStale session token cache file or other auth failure occurred. STATUS CODE: ${responseCode}", debug)

        // If we've already failed, then it must not be an auth issue
        if (alreadyFailed) {
            LMDebugPrint("\n\tAlready tried resetting token cache file. Exiting...", debug)
            return null
        }

        // Otherwise, try getting a fresh token
        // Clear cache file, we failed so it must not be good
        File tokenCacheFile
        if (props.collplat == 'windows') tokenCacheFile = new File("juniper_tokens" + '\\' +  props.host + "-juniper_mist_tokens.txt")
        if (props.collplat == 'linux') tokenCacheFile = new File("juniper_tokens" + '/' + props.host + "-juniper_mist_tokens.txt")
        if (tokenCacheFile.exists()) {
            tokenCacheFile.text = ''
            LMDebugPrint("\tCleared stale session token cache file", debug)
        }

        // Login and store new value in cache file
        LMDebugPrint("\tRelogging in...", debug)
        token = login(props, baseUrl, proxyInfo, debug)
        tokenCacheFile << token
        LMDebugPrint("\tReset session token cache file.\n\tFetching /${endpoint}", debug)

        return httpGet(props, endpoint, baseUrl, page, start, end, proxyInfo, debug, alreadyFailed=true)
    }
         // adding 429 response-code handler
    if (responseCode == 429) {
        def retryIn = conn.getHeaderField('Retry-After')
        // Default to 5 seconds if we don't get a retry after header.
        if (retryIn == null) retryIn = 5
        else retryIn = retryIn.toInteger()
        LMDebugPrint("Sleeping and retrying in ${retryIn}s after recieving a 429 response", debug)
        sleep(retryIn * 1000)
        // not an auth issue so we can retry
        return httpGet(props, endpoint, baseUrl, page, start, end, proxyInfo, debug, alreadyFailed=true)
    }

    LMDebugPrint("\tCould not fetch from /${endpoint}", debug)

    return null
}

def getLMDeviceDatasourceID(props,dsName){
    LMDebugPrint("Inside LM Get Device function", debug)
    epoch = System.currentTimeMillis();
    def resourcePath = "/device/devices/${props.deviceId}/devicedatasources"
    def filter = "?filter=dataSourceName:${dsName}"
    def queryParams = "&fields=id"
    def url = "https://" + props.lmAccount + ".logicmonitor.com" + "/santaba/rest" + resourcePath + filter + queryParams;
    
    //calculate signature
    requestVars = "GET" + epoch + resourcePath;

    try {
        hmac = Mac.getInstance("HmacSHA256");
        secret = new SecretKeySpec(props.lmAccessKey.getBytes(), "HmacSHA256");
        hmac.init(secret);
        hmac_signed = Hex.encodeHexString(hmac.doFinal(requestVars.getBytes()));
        signature = hmac_signed.bytes.encodeBase64();

        // HTTP Get
        CloseableHttpClient httpclient = HttpClients.createDefault();
        httpGet = new HttpGet(url);
        httpGet.addHeader("Authorization" , "LMv1 " + props.lmAccessId + ":" + signature + ":" + epoch);
        response = httpclient.execute(httpGet);
        responseBody = EntityUtils.toString(response.getEntity());
        code = response.getStatusLine().getStatusCode();

        // Print Response
        LMDebugPrint ("Status: = ${code}", debug);
        //println "Body:" + responseBody;

        httpclient.close();
        slurper = new JsonSlurper()
        def jsonResponse = slurper.parseText(responseBody);

        LMDebugPrint ("LM_Datasource-Response: = ${jsonResponse}", debug);

        devicedatasourceids = jsonResponse?.'data'?.'items'
        
        for(def devicedatasourceid : devicedatasourceids) {
                LM_DevicedatasourceID = devicedatasourceid.id
                LMDebugPrint("Device DatasourceID for ${props.hostDisplayName} = ${LM_DevicedatasourceID}", debug)

        }
        //Function to fetch the LM vManage Device datasource device list
        getLMDatasourceDevices(props, LM_DevicedatasourceID)
        //LMDebugPrint("LMActiveAlarms = ${LMActiveAlarms}", debug)
    }
    catch(Exception exc) {
        LMDebugPrint("\tAn exception occurred in getLMDeviceDatasourceID from LM.\n\tException: ${exc}",debug)
        return false
    }

}

def getLMDatasourceDevices(props, LMDeviceDatasourceID) {
    epoch = System.currentTimeMillis();
    LMDebugPrint("DeviceID=${props.deviceId}\n and LMDeviceDatasourceID=${LMDeviceDatasourceID}", debug)
    def count = 0
    def done = 0
    def i=1
    while (done==0)
   {
    def resourcePath = "/device/devices/${props.deviceId}/devicedatasources/${LMDeviceDatasourceID}/instances"
    def filter = "?filter=stopMonitoring:false"
    //def queryParams = "&fields=displayName,description,stopMonitoring&offset=${count}&size=500"
    def queryParams = "&fields=displayName,description,stopMonitoring,customProperties&offset=${count}&size=500"
    def url = "https://" + props.lmAccount + ".logicmonitor.com" + "/santaba/rest" + resourcePath + filter + queryParams;


    //calculate signature
    requestVars = "GET" + epoch + resourcePath;

    try {
        hmac = Mac.getInstance("HmacSHA256");
        secret = new SecretKeySpec(props.lmAccessKey.getBytes(), "HmacSHA256");
        hmac.init(secret);
        hmac_signed = Hex.encodeHexString(hmac.doFinal(requestVars.getBytes()));
        signature = hmac_signed.bytes.encodeBase64();

        // HTTP Get
        CloseableHttpClient httpclient = HttpClients.createDefault();
        httpGet = new HttpGet(url);
        httpGet.addHeader("Authorization" , "LMv1 " + props.lmAccessId + ":" + signature + ":" + epoch);
        response = httpclient.execute(httpGet);
        responseBody = EntityUtils.toString(response.getEntity());
        code = response.getStatusLine().getStatusCode();

        // Print Response
        LMDebugPrint("Status: = ${code}", debug);
        //println "Body:" + responseBody;

        httpclient.close();
        slurper = new JsonSlurper()
        def jsonResponse = slurper.parseText(responseBody);
        Map LMDevices = [:]
        datasourceDevices = jsonResponse?.'data'?.'items'
        numDevices = datasourceDevices.size
        count += numDevices
        total = jsonResponse?.'data'?.'total'
        if(count == total)
        {
            LMDebugPrint("got all the CIs from LM", debug)
            done = 1
        }
        else
        {
            LMDebugPrint("Not get the complete CIs hence query again to LM", debug)
        }
        LMDebugPrint("Length(count) of the device is:${numDevices}", debug)
        
        for(def datasourceDevice : datasourceDevices) {

            DS_devices[datasourceDevice.displayName] = datasourceDevice.stopMonitoring
            for(def cProp : datasourceDevice.customProperties) {
                if (cProp.name == "CI.SysId") {
                    DS_devices[datasourceDevice.displayName+".sysId"] = cProp.value
                }
            }
        }

    LMDebugPrint("DS_devices = ${DS_devices}", debug)
        
    }
    catch(Exception exc) {
        println("\tAn exception occurred in getLMDatasourceDevices from LM.\n\tException: ${exc}")
        return false
    }
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

        //println(responseCode)
        //println(responseBody)

        if (responseCode == 200 && !responseBody.contains("html")) { // Failure typically has 200 status code and a returned html page
            LMDebugPrint("\tSUCCESS!",debug)
            LMDebugPrint("Raw output:\n\t${responseBody}\n\n")
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