package com.tailf.packages.ned.nsp;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.client.methods.HttpRequestBase;

import com.grack.nanojson.JsonObject;
import com.tailf.navu.NavuNode;
import com.tailf.ned.NedMux;
import com.tailf.ned.NedWorker;
import com.tailf.packages.ned.nedcom.JsonUtils;
import com.tailf.packages.ned.nedcom.NedComGenericBase;
import com.tailf.packages.ned.nedcom.NedHttpConnection;
import com.tailf.packages.ned.nedcom.restconf.NedComGenericRestConfBase;
import com.tailf.packages.ned.nedcom.restconf.NedRestConfCASAuthBase;
import com.tailf.packages.ned.nedcom.restconf.NedRestConfConnection;
import com.tailf.util.Base64;

public class NokiaNspRestConfNedGeneric extends NedComGenericRestConfBase {

    protected static String NED_SETTING_AUTH_BEARER_TOKEN_MODE = "connection/authentication/mode";
    protected static String NED_SETTING_AUTH_BEARER_TOKEN_VALUE = "connection/authentication/value";
    protected static String NED_SETTING_AUTH_BEARER_TOKEN_URL = "connection/authentication/token-request/url";

    protected static String AUTH_BEARER_TOKEN = "bearer-token";
    protected static String AUTH_BEARER_TOKEN_MODE_PROBE = "probe";
    protected static String AUTH_BEARER_TOKEN_MODE_STATIC = "static-token";
    protected static String BEARER_TOKEN_HEADER = "Authorization";

    // Name of CAS auth cookie
    protected static String CAS_COOKIE = "cookie";

    protected String authBearerTokenMode;
    protected String authBearerTokenURL;


    private class CASAuth extends NedRestConfCASAuthBase {
        public CASAuth(NedComGenericBase ned, String urlBase, boolean useSSL, boolean acceptAny, byte[] cert) {
            super(ned, urlBase, useSSL, acceptAny, cert);
        }
        @Override
        protected String createCasLoginString(String user, String password, String cookie) {
            return String.format("username=%s&password=%s&execution=%s&_eventId=submit&gelocation", user, password, cookie);
        }

        @Override
        protected void doCasAuthenticate(NedWorker worker, String path, String user, String password)
            throws Exception {
            InetAddress origIp = this.ip;
            int origPort = this.port;

            Map<String,String> urlInfo = new HashMap<>();
            urlInfo.put("path", path);
            urlInfo.put("query", "depth=1");
            // 1
            // Try get on original path. Shall always generate a redirect.
            logDebug(worker, "CAS authenticate step 1");
            if (!getWithRedirect(worker, urlInfo)) {
                throw new Exception("Could not trigger initial CAS redirect! (step 1)");
            }

            // 2
            // Execute a get towards the redirected URL
            // Will generate a new redirect and a NSPOS_JSESSIONID cookie
            logDebug(worker, "CAS authenticate step 2");
            if (!getWithRedirect(worker, urlInfo)) {
                throw new Exception("Failed to fetch JSESSION cookie! (step 2)");
            }

            // 3
            // Fetch the execution cookie by doing a get towards the redirected URL.
            // This shall not generate a new redirect
            logDebug(worker, "CAS authenticate step 3");
            resetConnection(worker, urlInfo);
            String dump = get(worker, urlInfo.get("path"), urlInfo.get("query"));

            Pattern p = Pattern.compile("id=\\\"execution\\\" +value=\\\"(\\S+)\\\"");
            Matcher m = p.matcher(dump);
            if (!m.find()) {
                throw new Exception("Could not find the execution cookie");
            }
            String executionCookie = m.group(1);
            logDebug(worker, String.format("Got execution cookie: %s", executionCookie));

            // 4
            // Now do CAS login
            // Will generate a new redirect and a TGC cookie
            logDebug(worker, "CAS authenticate step 4");
            doCasLogin(worker, urlInfo, createCasLoginString(user, password, executionCookie));

            // 5 - 9
            // Perform get operations until not redirected anymore
            // This will generate the JSESSION and ssoid cookies
            int i = 5;
            for (;i < 10; i++ ) {
                logDebug(worker, "CAS authenticate step " + i);
                if (!getWithRedirect(worker, urlInfo)) {
                    break;
                }
            }
            if (i == 10) {
                throw new Exception("Reached max number of CAS redirects");
            }

            urlInfo.put("ip",origIp.getHostAddress());
            urlInfo.put("port", Integer.toString(origPort));
            urlInfo.put("path", path);
            urlInfo.put("query", "depth=1");

            if (getWithRedirect(worker,urlInfo)) {
                throw new Exception("CAS authentication failed (final step)");
            }
            // Implement the CAS authentication steps here
        }
    }

    private class BearerTokenAuth extends NedHttpConnection {
        public BearerTokenAuth(NedComGenericBase ned,
                               boolean useSSL,
                               boolean acceptAny,
                               byte[] cert) {
            super(ned, "", useSSL, acceptAny, cert);
        }

        @Override
        protected void prepareMsg(NedWorker worker, HttpRequestBase msg) throws Exception {
            msg.addHeader("Accept",  "*/*");
            msg.addHeader("Content-type",  "application/x-www-form-urlencoded");

            String auth = String.format("%s:%s", user, password);
            msg.addHeader("Authorization", String.format("Basic %s", Base64.encodeBytes(auth.getBytes())));
        }

        /**
         * @param worker
         * @param msg
         */
        protected String getToken(NedWorker worker) throws Exception {
            connect(worker);
            Map<String,String> responseHeaders = new HashMap<>();
            logDebug(worker, "Getting token");
            logDebug(worker, authBearerTokenURL);

            /*
             * From Nokia Documentation:
             * Prior to sending any REST requests, the OSS application must first authenticate the user.
             * This is done by sending a POST request, using Basic authentication (base64 encoded credentials in the
             * form of username:password), to the /rest-gateway/authentication/rest/api/v1/token endpoint to
             * obtain a Bearer token which will be used for future communications:
             * https://<server>/rest-gateway/rest/api/v1/auth/token
             */
            String json = post(worker,
                               authBearerTokenURL,
                               null,
                               "grant_type=client_credentials",
                               responseHeaders);

            if (responseHeaders.containsKey(BEARER_TOKEN_HEADER)) {
                return responseHeaders.get(BEARER_TOKEN_HEADER).replaceAll("^Bearer *", "");
            }
            JsonObject response = JsonUtils.parse(json);
            return response.getString("token");
        }
    }


    private class NokiaNspConnection extends NedRestConfConnection {
        // Instance variable indicating bearer token probing is in progress
        private boolean isProbing = false;

        public NokiaNspConnection(NedWorker worker,
                                  NedComGenericBase ned,
                                  String userName,
                                  String password,
                                  String urlBase) throws Exception {
            super(worker, ned, userName, password, urlBase);
        }


        @Override
        protected void doCasAuthenticate(NedWorker worker, HttpRequestBase msg) throws Exception {
            if (!headers.containsKey(CAS_COOKIE)) {
                logDebug(worker, "Executing CAS authentication");
                CASAuth cas = new CASAuth(ned,
                                          authMethod,
                                          acceptAny || certificate != null,
                                          acceptAny,
                                          certificate);
                headers.put(CAS_COOKIE, cas.getCasCookies(worker, msg.getURI().getPath(), userName, password));
            }
        }

        /**
         * @param worker
         * @param msg
         */
        @Override
        protected void doCustomAuthenticate(NedWorker worker, HttpRequestBase msg) {
            if ((AUTH_BEARER_TOKEN.equals(authMethod)) && !headers.containsKey(BEARER_TOKEN_HEADER)) {
                logDebug(worker, "Creating bearer token auth header");
                boolean doProbe = AUTH_BEARER_TOKEN_MODE_PROBE.equals(authBearerTokenMode);
                if (!doProbe) {
                    String token = ned.nedSettings.getString(NED_SETTING_AUTH_BEARER_TOKEN_VALUE);
                    if (token == null) {
                        logError(worker, "No token value found");
                        return;
                    }
                    headers.put(BEARER_TOKEN_HEADER, String.format("Bearer %s",token));
                } else if (!isProbing) {
                    try {
                        isProbing = true;
                        BearerTokenAuth tokenAuth = new BearerTokenAuth(ned, acceptAny || certificate != null, acceptAny, certificate);
                        headers.put(BEARER_TOKEN_HEADER, String.format("Bearer %s", tokenAuth.getToken(worker)));
                    } catch (Exception e) {
                        isProbing = false;
                        ned.logError(worker, "Failed to authenticate with bearer token");
                    }
                }
            }
        }
    }


    /**
     * Default constructor.
     */
    public NokiaNspRestConfNedGeneric() {
        super();
    }

    /**
     * Constructor
     *
     *
     * @param device
     *            - Device id
     * @param mux
     *            - NED Mux
     * @param worker
     *            - NED Worker
     * @throws Exception
     */
    public NokiaNspRestConfNedGeneric(String deviceId, NedMux mux, boolean trace,
                                      NedWorker worker) throws Exception {
        super(deviceId, mux, trace, worker);
    }

    /**
     * Apply JSON transforms on outbound messages. This method is intended
     * to be used by the inheriting sub class for doing custom adaptions of
     * of the messages for devices that deviate from the RESTCONF specification.
     * @param node - Corresponding node in config tree.
     * @param path - The RESTCONF path to be used when doing the operation.
     * @param json - JSON object containing the data below the node.
     * @param op   - The RESTCONF operation to be used.
     * @return transformed JSON object
     */
    @Override
    protected JsonObject applyOutboundTransforms(NavuNode node, StringBuilder path,
                                                 JsonObject json, OutBoundOp op) throws Exception {
        // Override and customize in sub class
        return json;
    }


    /**
     * Apply JSON transforms on in bound messages. This method is intended
     * to be used by the inheriting sub class for doing custom adaptions of
     * of the messages for devices that deviate from the RESTCONF specification.

     * The method is called twice. First before the GET call, then again after.
     * Makes it possible to first transform the path, then the fetched payload.
     * @param node - Corresponding node in config tree.
     * @param path - Path to be used in the RESTCONF GET operation
     * @param json - JSON object containing the data to be populated under
     *               the node.
     * @return transformed JSON object
     */
    @Override
    protected JsonObject applyInboundTransforms(NavuNode node, StringBuilder path,
                                                JsonObject config) throws Exception {
        // Override and customize in sub class
        return config;
    }

    /**
     * Instantiate a custom RESTCONF Client. Only needed if the subclass
     * needs to instantiate a custom RESTCONF client.
     *
     * For example if adaptions need to be  made for special authentication
     * towards the device.
     * @param worker - The NED worker
     * @throws Exception
     */
    @Override
    protected void createConnection(NedWorker worker) throws Exception {
        restconf = new NokiaNspConnection(worker, this, user, password, urlBase);
    }

    /**
     * Read all NED settings and setup instance variables accordingly.
     * Can be extended/overridden by the inheriting sub class.
     * @throws Exception
     */
    @Override
    protected void readNedSettings(NedWorker worker) throws Exception {
        if (AUTH_BEARER_TOKEN.contentEquals(nedSettings.getString(NedComGenericRestConfBase.NED_SETTING_AUTH_METHOD))) {
            authBearerTokenMode = nedSettings.getString(NED_SETTING_AUTH_BEARER_TOKEN_MODE, AUTH_BEARER_TOKEN_MODE_STATIC);
            authBearerTokenURL = nedSettings.getString(NED_SETTING_AUTH_BEARER_TOKEN_URL, String.format("%s/auth", this.urlBase));
        }
        super.readNedSettings(worker);
    }

    /**
     * Print out how the NED is configured. This configuration has been set
     * either through NED settings and/or hard coded via a profile.
     * Can be extended/overridden by the inheriting sub class.
     * @param worker - The NED worker thread.
     */
    @Override
    protected void printNedSettings(NedWorker worker) {
        super.printNedSettings(worker);
    }

}
