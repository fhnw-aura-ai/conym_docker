
import io.jans.model.custom.script.type.authzchallenge.AuthorizationChallengeType;
import io.jans.as.model.jwt.Jwt;
import io.jans.model.custom.script.model.CustomScript;
import io.jans.service.custom.script.CustomScriptManager;
import io.jans.model.SimpleCustomProperty;
import io.jans.as.server.service.external.context.ExternalScriptContext;
import io.jans.as.model.configuration.AppConfiguration;
import io.jans.as.common.model.registration.Client;
import io.jans.as.common.model.common.User;
import io.jans.as.common.service.common.UserService;
import io.jans.as.server.service.AuthenticationService;

import io.jans.service.cdi.util.CdiUtil;
import io.jans.as.server.model.common.AuthorizationGrantList;
import io.jans.as.server.model.common.AuthorizationGrant;
import io.jans.as.server.model.common.AbstractToken;
import io.jans.as.server.service.net.HttpService;
import io.jans.as.server.model.net.HttpServiceResponse;

import org.apache.http.HttpResponse;
import org.apache.http.entity.ContentType;
import jakarta.servlet.http.HttpServletRequest;
import com.google.common.io.BaseEncoding;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.time.*;
import java.util.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.net.URLEncoder;
import java.net.URI;
import java.util.stream.IntStream;

import org.json.JSONObject;
import org.json.JSONArray;

import ch.fhnw.imvs.ai.aura.ConymUserManager;
import ch.fhnw.imvs.ai.aura.ConymClientManager;
import ch.fhnw.imvs.ai.aura.ConymAnalytics;

public class TokenExchange implements AuthorizationChallengeType {

    private static final Logger log = LoggerFactory.getLogger(CustomScriptManager.class);

    private static final String ID_TOKEN_PARAM_KEY = "id_token";
    private static final String ACCESS_TOKEN_PARAM_KEY = "access_token";
    private static final String SCOPE_PARAM_KEY = "scope";
    private static final String ISSUER_PARAM_KEY = "issuer";

    private static final String ISSUER_USER_INFO_URI_KEY = "userinfo_uri";
    private static final String ISSUER_INTROSPECTION_URI_KEY = "introspection_uri";

    private static final String DEFAULT_ISSUER_CONFIG_KEY = "default_issuer";
    private static final String APPROVED_ISSUERS_CONFIG_KEY = "approved_issuer";
    private static final String BEARER_AUTH_HEADER = "Bearer ";
    private static final String BASIC_AUTH_HEADER = "Basic ";

    //Todo: when filling make sure it uses https
    private final Map<String, JSONObject> approvedIssuers = new HashMap<String, JSONObject>();
    private String defaultIssuer = null;

    private static String usedSubjectIdDefaultMethod = null;
    private static String usedSubjectIdDefaultAttribute = null;

    private String selfIssuer = null;

    //Todo: Move to claim manager to share with delegate Auth
    //Todo: In future can we set per provider!!!
    //Note: The value in the Map is the expected type
    private final Map<String,String> requiredClaims = new HashMap<>();
    private final Map<String,String> desiredClaims = new HashMap<>();
    private final Map<String,String> optionalClaims = new HashMap<>();

    private AppConfiguration appConfig = null;
    private UserService userService = null;
    private AuthenticationService authenticationService = null;
    private HttpService httpService = null;

    @Override
    public boolean init(Map<String, SimpleCustomProperty> configurationAttributes) {
        log.info("Token Exchange. Initializing...");

        appConfig = CdiUtil.bean(AppConfiguration.class);
        userService = CdiUtil.bean(UserService.class);
        authenticationService = CdiUtil.bean(AuthenticationService.class);
        httpService = CdiUtil.bean(HttpService.class);

        if(!ConymUserManager.init(appConfig)) return false;
        //This will preregister some clients if not done already
        if(!ConymClientManager.init(appConfig)) return false;

        selfIssuer = appConfig.getIssuer();
        if(selfIssuer == null) {
            selfIssuer = System.getenv("WEBHOST_NAME");
        } else {
            selfIssuer = URI.create(selfIssuer).getHost();
        }

        if(selfIssuer == null) {
            log.error("Token Exchange. Could not determin current issuer");
            return false;
        }

        if(configurationAttributes.containsKey("subject_id_method")){
            usedSubjectIdDefaultMethod = configurationAttributes.get("subject_id_method").getValue2();
        }

        if(configurationAttributes.containsKey("subject_id_attribute")){
            usedSubjectIdDefaultMethod = configurationAttributes.get("subject_id_attribute").getValue2();
        }

        //Todo: improve, use same config files as Authentication
        if (configurationAttributes.containsKey("approved_issuer_files")) {
            log.info("Token Exchange. Using Token Issuer Config File: "+configurationAttributes.get("approved_issuer_files").getValue2());
            JSONArray issuerCredsFiles = new JSONArray(configurationAttributes.get("approved_issuer_files").getValue2());
            for(int i = 0; i < issuerCredsFiles.length(); i++){
                String issuerCredsFile = issuerCredsFiles.get(i).toString();
                JSONObject issuer;
                try {
                    issuer = new JSONObject(new String(Files.readAllBytes(Paths.get(issuerCredsFile))));
                    approvedIssuers.put(issuer.getString("op_server"),issuer) ;
                    log.info("Token Exchange. Enabled following token issuer: "+issuer.getString("op_server"));
                } catch (Exception e){
                    log.error("Token Exchange. Reading token issuer failed",e);
                    return false;
                }
                if(issuer.optBoolean("default",false)){
                    if(defaultIssuer != null) {
                        log.error("Token Exchange. Only one default token issuer allowed");
                        return false;
                    }
                    defaultIssuer = issuer.getString("op_server");
                }
            }
        }

        if(configurationAttributes.containsKey("required_user_claims")){
            log.info("Token Exchange. Using Required Extra Claims (email always required): "+configurationAttributes.get("required_user_claims").getValue2());
            JSONArray reqClaimConf = new JSONArray(configurationAttributes.get("required_user_claims").getValue2());
            IntStream.range(0, reqClaimConf.length()).mapToObj(reqClaimConf::getString).forEach(s -> parseClaim(requiredClaims,s));
        }

        if(configurationAttributes.containsKey("desired_user_claims")){
            log.info("Token Exchange. Using Desired Claims: "+configurationAttributes.get("desired_user_claims").getValue2());
            JSONArray desClaimConf = new JSONArray(configurationAttributes.get("desired_user_claims").getValue2());
            IntStream.range(0, desClaimConf.length()).mapToObj(desClaimConf::getString).forEach(s -> parseClaim(desiredClaims,s));
        }

        if(configurationAttributes.containsKey("optional_user_claims")){
            log.info("Token Exchange. Using Optional Claims: "+configurationAttributes.get("desired_user_claims").getValue2());
            JSONArray optClaimConf = new JSONArray(configurationAttributes.get("desired_user_claims").getValue2());
            IntStream.range(0, optClaimConf.length()).mapToObj(optClaimConf::getString).forEach(s -> parseClaim(optionalClaims,s));
        }

        log.info("Token Exchange.  Initialized.");
        return true;
    }

    @Override
    public boolean init(CustomScript customScript, Map<String, SimpleCustomProperty> configurationAttributes) {
        return init(configurationAttributes);
    }

    @Override
    public boolean destroy(Map<String, SimpleCustomProperty> configurationAttributes) {
        log.info("Token Exchange. Destroyed Java custom script.");
        return true;
    }

    @Override
    public int getApiVersion() {
        return 11;
    }

    private JSONObject getUserInfo(JSONObject issuerData, String accessToken) {
        String userinfoEndpoint = issuerData.getString(ISSUER_USER_INFO_URI_KEY);
        return makeAuthorizedRequest(userinfoEndpoint,accessToken);
    }

    private User authorizeLocal(String accessToken, AuthorizationGrant authorizationGrant, ExternalScriptContext context){
        log.info("Token Exchange. Local Exchange Request Received for user "+authorizationGrant.getUser().getUserId());

        HttpServletRequest request = context.getHttpRequest();
        String issuer = request.getParameter(ISSUER_PARAM_KEY);
        if(request.getParameter(ISSUER_PARAM_KEY) != null) {
            if(!issuer.equals(selfIssuer)){
                log.warn("Token Exchange. External issuer is only allowed for external tokens, got {} for an internal token", issuer);
                log.debug("  This is: "+selfIssuer);
                return null;
            }
        }

        //Check if the assosiated token is valid
        final AbstractToken accessTokenObject = authorizationGrant.getAccessToken(accessToken);
        if (accessTokenObject == null || !accessTokenObject.isValid()) {
            log.debug("Token Exchange. Invalid local access token object");
            return null;
        }
        return authorizationGrant.getUser();
    }

    //Todo: move to shared claim Manager
    private void parseClaim(Map<String, String> claims, String raw) {
        if(raw == null) return;
        String[] parts = raw.split(":",2);
        switch (parts.length) {
            case 0:
            case 1:
                claims.put(raw,"object");
                return;
            case 2:
                claims.put(parts[0],parts[1]);
                return;
            default:
                log.error("Delegated Authentication. Missformated claim takeover configuration: {}", raw);
                return;
        }
    }



    private User authorizeExternal(String accessToken, ExternalScriptContext context){
        log.info("Token Exchange. External Exchange Request Received");
        log.info("      Starting issuer identification");
        HttpServletRequest request = context.getHttpRequest();
        String issuer = request.getParameter(ISSUER_PARAM_KEY);
        if(issuer == null) {
            log.trace("Token Exchange. No issuer was provided, will try to extract from token");
            Jwt accessTokenJwt = Jwt.parseSilently(accessToken);
            if (accessTokenJwt != null) {
                issuer = accessTokenJwt.getClaims().getClaimAsString("iss");
            }
        }

        if(issuer == null && defaultIssuer != null) {
            log.trace("Token Exchange. Could not extract issuer from token will use defautl issuer");
            issuer = defaultIssuer;
        }

        if(issuer == null && approvedIssuers.size() == 1) {
            log.trace("Token Exchange. Could not extract issuer from token will use only registered issuer as fallback");
            issuer = approvedIssuers.keySet().iterator().next();
        }

        if(issuer == null) {
            log.warn("Token Exchange. Could not establish token issuer");
            //Todo: use default provider instead??
            //      or try all??
            // In theory we could filter out
            return null;
        }

        log.info("      Issuer iddentified as "+issuer);
        JSONObject issuerData = approvedIssuers.get(issuer);
        if(issuerData == null) {
            log.warn("Token Exchange. Issuer "+issuer+" is not approved for Token Exchange");
            return null;
        }

        log.info("      Starting user identification");

        String sub = null;
        User user = null;

        Client requestingClient = context.getExecutionContext().getClient();

        //It is important that this is first
        // 1: OIDC compatability
        // 2: Introspection may be protected
        //    If so the own access token may not give access to it
        //  Note: This may be an oppertunity: to handle pseudonymisation stuff
        //  However: if user info is avaiable it must be adapted to not leak stuff
        //    Thus doing it first ensures no security whole
        //    (Basically we actively attack ourself to ensure its safe)

        //Todo: First do id token if avaiable??? <-- it is not here
        //      Instaed firsat do Jwt access token <-- needs verify

        JSONObject userInfo = getUserInfo(issuerData,accessToken);
        if(userInfo != null) {
            log.trace("Token Exchange.  Extracting user data from user info response");
            if(sub == null && userInfo.has("sub")) {
                sub = userInfo.getString("sub");
                log.info("      User subject identified as "+sub);
                //If this is a user we already have just fetch it
                //Note: For safety reasons externals must be bound pairwise
                //       If we dont't their is the risk of impersonation attacks
                //  Example: We have a user with uid: XYZ
                //           We give it out public, so other would get XYZ as sub
                //           Attacker creates a user named XYZ
                //           The uid becomes XYZ on other conym
                //           User logs in
                //           User requests access token exchange.
                //           We see its external (end up here)
                //           As we gave out public we assume our uid and their sub are equal
                //           We find our XYZ user
                //           We hand out a token
                //           Attacker has sucessfully impersonated our XYZ

                //By using pairwise it does not work:
                //   1. If user has never authenticated with us, their is no mapping
                //   2. If user has authenticated with us, then the attacker would get a user already exists error

                user = ConymUserManager.resolveUserPairwise(sub);
                if(user != null){
                    log.info("      User resolved to "+user.getUserId());
                } else {
                    log.info("      User resolution failed");
                };
            }
        } else {
            log.warn("Token Exchange. Access Token was not accepted by issuer {} for Userinfo", issuer);
        }

        if(sub == null) {
            log.warn("Token Exchange. Incapable of fetching and verifying sub from issuer {}", issuer);
            return null;
        }

        if(user == null) {
            //Resolve the claims:
            Map<String,Object> attrs = new HashMap<>();
            Map<String, String> reqClaims = new HashMap<>(requiredClaims);
            Map<String, String> desClaims = new HashMap<>(desiredClaims);
            Map<String, String> optClaims = new HashMap<>(optionalClaims);
            ConymUserManager.collectAttrsFromAllClaims(attrs, userInfo, reqClaims, desClaims, optClaims);

            //use the introspection if reqClaims || desClaims is non-empty or if already resolved for sub

            if(!reqClaims.isEmpty()) {
                log.warn("Token Exchange. Incapable of fetching {}", reqClaims.keySet());
                return null;
            }
            log.debug("Token Exchange. User with sub did not exist locally, wiil try to map it to a new default external user");
            user = ConymUserManager.addUser(issuerData.getString("op_server"), sub, attrs);
        } else {
            log.debug("Token Exchange. User with external sub {} was mapped to internal user with id", sub, user.getUserId());
        }
        return user;
    }

    //@Override
    public void prepareAuthzRequest(Object scriptContext){
        return;
    }

    //Currently we do no scope mapping, whatever the client request it gets if it has it.
    //  The client is responsible - which is fair
    //  If the client wanted he could use clientCredential to get all those scopes anyway
    //  Proacc needs to have 2 things:
    //    1. Validate some scopes ahead of time (validate exsts)
    //    2. Map some scopes from source to target scopes
    //    3. Have some scope filter (if access token has scope pass it allong)
    @Override
    public boolean authorize(Object scriptContext) {
        log.trace("Token Exchange. Exchange Request received");
        ExternalScriptContext context = (ExternalScriptContext) scriptContext;
        /*String idToken = request.getParameter(ID_TOKEN_PARAM_KEY);
        if (idToken != null) {
            //Todo: In the future support OIDC idToken
            //      Not yet needed we have access tokens
            log.info("Token Exchange. Only Access Tokens are supported");
            return false;
        }*/

        String accessToken = extractAccessToken(context);
        if (accessToken == null) {
            log.warn("Token Exchange. No Access Tokens was provided");
            return false;
        }

        //Todo: split path for own tokens and external tokens - only support pairwise for externals
        //       otherwise we risk user impersonation attacks if the source allows the user to choose th uid (by mapping it to username)
        AuthorizationGrantList authorizationGrantList = CdiUtil.bean(AuthorizationGrantList.class);
        AuthorizationGrant authorizationGrant = authorizationGrantList.getAuthorizationGrantByAccessToken(accessToken);
        User user = null;
        if (authorizationGrant != null) {
            log.trace("Token Exchange. Exchanging self issued token");
            if(authorizationGrant.getUser() == null) {
                log.warn("Token Exchange. No user assosiated with access token. Make sure access token lifetime is smaller than user expiration time");
                return false;
            }
            //We have issued the token
            user = authorizeLocal(accessToken, authorizationGrant, context);
        } else {
            log.trace("Token Exchange. Exchanging external issued token");
            //Someone else has issued the token
            user = authorizeExternal(accessToken, context);
        }

        if(user != null) {
            //Todo: Is this needed or would the set user be enough?
            //      We do not necessarely need a session. However the Authorization Grant may need it
            boolean res = authenticationService.authenticate(user.getUserId());
            if (res) {
                context.getExecutionContext().setUser(user); // <- IMPORTANT : without user set, user relation will not be associated with new token
                log.info("Token Exchange - Token Exchange for User {} suceeded", user.getUserId());
            } else {
                //should not happen
                log.error("Token Exchange - Failed to authenticate remote User {} locally", user.getUserId());
            }
            return res;
        }
        log.warn("Token Exchange - Failed to find or create local user");
        log.debug("Token Exchange - Make sure that external access tokens are issued from a conym that uses a pairwise (subject_type) client to comunicate with this conym");
        return false;
    }

    //  Jnssen had a strange interface addition - so without override it works independent on when the janssen image was loaded
    //@Override
    public Map<String, String> getAuthenticationMethodClaims(Object context){
        return Map.of();
    }

    private String extractAccessToken(ExternalScriptContext context){
        HttpServletRequest request = context.getHttpRequest();
        String accessToken = request.getParameter(ACCESS_TOKEN_PARAM_KEY);
        //Todo: Remove this it seems not to work - retest (may have been another error)
        //      Probably a earlier layer tries to validate the token
        //      In that case this is still fine for local requests
        if(accessToken == null) {
            String authHeader = request.getHeader("Authorization");
            if(authHeader != null && authHeader.startsWith(BEARER_AUTH_HEADER)){
                log.trace("Token Exchange - Access Token was extracted from Authorisation header");
                accessToken = authHeader.substring(BEARER_AUTH_HEADER.length());
            }
        }
        return accessToken;
    }

    private JSONObject makeAuthorizedRequest(String uri, String accessToken){
        try{
            Map<String, String> requestHeaders = Map.of(
                    "Authorization", BEARER_AUTH_HEADER+accessToken,
                    "Accept", "application/json"
            );

            HttpServiceResponse resultResponse = httpService.executeGet(
                    httpService.getHttpsClient(),
                    uri,
                    requestHeaders);

            HttpResponse httpResponse = resultResponse.getHttpResponse();
            int httpResponseStatusCode = httpResponse.getStatusLine().getStatusCode();
            if(httpResponseStatusCode != 200){
                log.info("Token Exchange - request to {} failed with code: {} ",uri,httpResponseStatusCode);
                return null;
            }

            byte[] responseBytes = httpService.getResponseContent(httpResponse);
            String responseString = httpService.convertEntityToString(responseBytes);
            return new JSONObject(responseString);
        } catch (Exception e){
            log.error("Token Exchange - Exception during remote request to "+uri, e);
        }
        return null;
    }

}