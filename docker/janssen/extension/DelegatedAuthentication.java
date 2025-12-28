import java.util.*;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;

import io.jans.as.model.exception.InvalidJwtException;
import io.jans.model.custom.script.type.auth.PersonAuthenticationType;
import io.jans.as.server.security.Identity;
import io.jans.model.security.Credentials;
import io.jans.service.cdi.util.CdiUtil;
import io.jans.as.server.service.AuthenticationService;
import io.jans.service.UserAuthenticatorService;
import io.jans.model.user.authenticator.UserAuthenticator;
import io.jans.as.model.configuration.AppConfiguration;
import io.jans.as.common.service.common.UserService;
import io.jans.as.common.model.common.User;

import io.jans.util.StringHelper;
import io.jans.model.SimpleCustomProperty;
import io.jans.model.AuthenticationScriptUsageType;
import io.jans.model.custom.script.model.CustomScript;
import io.jans.service.custom.script.CustomScriptManager;
import io.jans.as.server.util.ServerUtil;
import io.jans.orm.PersistenceEntryManager;
import io.jans.jsf2.service.FacesService;
import io.jans.as.model.jwt.Jwt;

import io.jans.as.server.i18n.LanguageBean;

import io.jans.as.server.service.net.HttpService;
import io.jans.as.server.model.net.HttpServiceResponse;
import jakarta.servlet.http.HttpServletRequest;

import org.apache.http.HttpResponse;
import com.google.common.io.BaseEncoding;

import org.json.JSONObject;
import org.json.JSONArray;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.time.*;
import java.util.stream.IntStream;
import java.util.Locale;

import ch.fhnw.imvs.ai.aura.ConymUserManager;
import ch.fhnw.imvs.ai.aura.ConymClientManager;
import ch.fhnw.imvs.ai.aura.ConymAnalytics;

public class DelegatedAuthentication implements PersonAuthenticationType {

    private static final Logger log = LoggerFactory.getLogger(CustomScriptManager.class);

    public final static int LOCAL_PROVIDER = -1;
    public final static int SELECT_PROVIDER = -2;
    //Jansen seems not to accept custom attributes thus we add it as login hint
    public final static String PROVIDER_SELECTOR_PROPERTY = "login_hint";
    private final static String PAGE = "/auth/delegated_authentication.xhtml";
    
    private JSONObject[] oidcCreds;
    private int defaultProvider = SELECT_PROVIDER;

    private boolean allowLocalLogin;

    private String baseUri;

    //Todo: In future can we set per provider!!!
    //Note: The value in the Map is the expected type
    private final Map<String,String> requiredClaims = new HashMap<>();
    private final Map<String,String> desiredClaims = new HashMap<>();
    private final Map<String,String> optionalClaims = new HashMap<>();

    private PersistenceEntryManager entryManager = null;
    private AppConfiguration appConfig = null;
    private FacesService facesService = null;
    private LanguageBean languageBean = null;

    private UserAuthenticatorService userAuthService = null;
    private AuthenticationService authenticationService = null;
    private UserService userService = null;
    private HttpService httpService = null;

    @Override
    public boolean init(Map<String, SimpleCustomProperty> configurationAttributes) {
        log.info("Delegated Authentication. Initializing ...");
        entryManager = CdiUtil.bean(PersistenceEntryManager.class);
        appConfig = CdiUtil.bean(AppConfiguration.class);
        facesService = CdiUtil.bean(FacesService.class);
        languageBean = CdiUtil.bean(LanguageBean.class);
        authenticationService = CdiUtil.bean(AuthenticationService.class);
        userService = CdiUtil.bean(UserService.class);
        httpService = CdiUtil.bean(HttpService.class);
        userAuthService = CdiUtil.bean(UserAuthenticatorService.class);

        if(!ConymUserManager.init(appConfig)) return false;
        //This will preregister some clients if not done already
        if(!ConymClientManager.init(appConfig)) return false;
        if(!ConymAnalytics.init(appConfig)) return false;
        String host = System.getenv("WEBHOST_NAME");
        if(host == null) {
            log.error("Delegated Authentication. Could not load base Uri");
            return false;
        }

        String port = System.getenv("WEBHOST_PORT_SSL");
        if(port == null || "443".equals(port)){
            baseUri = "https://"+host;
        } else {
            baseUri = "https://"+host+":"+port;
        }

        log.info("Delegated Authentication. Using following base uri for redirects: "+baseUri);

        allowLocalLogin = true;
        if (configurationAttributes.containsKey("disable_local_login")) {
            String disableLocalLogin = configurationAttributes.get("disable_local_login").getValue2();
            if("true".equals(disableLocalLogin)){
                allowLocalLogin = false;
            } else if(!("false".equals(disableLocalLogin))){
                log.error("Delegated Authentication. disable_local_login must be true or false if present");
                return false;
            }
        }

        if (configurationAttributes.containsKey("oidc_cred_files")) {
            log.info("Delegated Authentication. Using OIDC Config File: "+configurationAttributes.get("oidc_cred_files").getValue2());
            JSONArray oidcCredsFiles = new JSONArray(configurationAttributes.get("oidc_cred_files").getValue2());
            oidcCreds = new JSONObject[oidcCredsFiles.length()];
            for(int i = 0; i < oidcCreds.length; i++){
                String oidcCredsFile = oidcCredsFiles.get(i).toString();
                try {
                    oidcCreds[i] = new JSONObject(new String(Files.readAllBytes(Paths.get(oidcCredsFile))));
                    log.info("Delegated Authentication. Enabled following OIDC Provider: "+oidcCreds[i].getString("op_server"));
                } catch (Exception e){
                    log.error("Delegated Authentication. Reading Inbound OIDC failed",e);
                    return false;
                }
                if(oidcCreds[i].optBoolean("default",false)){
                    if(defaultProvider != SELECT_PROVIDER) {
                        log.error("Delegated Authentication. Only one default OIDC provider allowed");
                        return false;
                    }
                    defaultProvider = i;
                }
            }
        } else {
            //Use as marker to disable feature
            if(!allowLocalLogin) {
                log.error("Delegated Authentication. OIDC forwarding must be configured when local login is disabled");
                return false;
            } else {
                oidcCreds = null;
                log.info("Delegated Authentication. No Inbound OIDC configured - fallback to local authentication");
            }
        }

        if(!allowLocalLogin) {
            log.info("Delegated Authentication. Disabling Local Login");
        } else {
            log.info("Delegated Authentication. Enabling Local Login");
        }

        if(configurationAttributes.containsKey("default_provider")){
            String defaultProviderString = configurationAttributes.get("default_provider").getValue2();
            if(defaultProvider != SELECT_PROVIDER) {
                log.info("Delegated Authentication. Overwriting Default provider with "+defaultProviderString);
            } else {
                log.info("Delegated Authentication. Using "+defaultProviderString+" as default provider");
            }

            if("all".equals(defaultProviderString) || "select".equals(defaultProviderString) || "*".equals(defaultProviderString)) {
                defaultProvider = SELECT_PROVIDER;
            } else if("local".equals(defaultProviderString) || ".".equals(defaultProviderString)){
                if(!allowLocalLogin) {
                    log.error("Delegated Authentication. Can not use local as default when disable_local_login = true");
                    return false;
                }
                defaultProvider = LOCAL_PROVIDER;
            } else if(oidcCreds != null && oidcCreds.length > 0) {
                //To detect failure afterwards
                defaultProvider = SELECT_PROVIDER;
                for(int i = 0; i < oidcCreds.length; i++) {
                    if(oidcCreds[i].getString("op_server").equals(defaultProviderString)) {
                        defaultProvider = i;
                        break;
                    }
                }
                if(defaultProvider == SELECT_PROVIDER) {
                    log.error("Delegated Authentication. Did not find provider "+getProviderName(defaultProvider)+" in active providers");
                    return false;
                }
            } else {
                log.error("Delegated Authentication. Did not find provider "+getProviderName(defaultProvider)+" as no custom providers are active");
                return false;
            }
        } else {
            //Was not overwritten and not explicitly set (otherwise we are not in this else branch))
            if(defaultProvider == SELECT_PROVIDER){
                if((oidcCreds == null || oidcCreds.length == 0) && allowLocalLogin){
                    defaultProvider = LOCAL_PROVIDER;
                    log.info("Delegated Authentication. Using local login as default");
                } else {
                    log.info("Delegated Authentication. Using provider select login as default");
                }
            }
        }

        if(configurationAttributes.containsKey("required_user_claims")){
            log.info("Token Exchange. Using Required Claims: "+configurationAttributes.get("required_user_claims").getValue2());
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

        log.info("Delegated Authentication. Initialized.");
        return true;
    }

    @Override
    public boolean init(CustomScript customScript, Map<String, SimpleCustomProperty> configurationAttributes) {
        return init(configurationAttributes);
    }

    @Override
    public boolean destroy(Map<String, SimpleCustomProperty> configurationAttributes) {
        log.info("Delegated Authentication. Destroyed");
        return true;
    }

    @Override
    public int getApiVersion() {
        return 11;
    }

    @Override
    public Map<String, String> getAuthenticationMethodClaims(Map<String, SimpleCustomProperty> configurationAttributes){
        return null;
    }

    @Override
    public boolean isValidAuthenticationMethod(AuthenticationScriptUsageType usageType, Map<String, SimpleCustomProperty> configurationAttributes){
        return true;
    }

    @Override
    public String getAlternativeAuthenticationMethod(AuthenticationScriptUsageType usageType,  Map<String, SimpleCustomProperty> configurationAttributes){
        return null;
    }
    // This is called first to see what to render
    @Override
    public String getPageForStep(Map<String, SimpleCustomProperty> configurationAttributes, int step){
        int[] targetedProvider = getTargetProvider();
        //Todo: For know until better solution
        languageBean.setLocale(Locale.ENGLISH);

        if(targetedProvider[0] == LOCAL_PROVIDER) return "";
        if(oidcCreds != null && step == 1) return PAGE;
        return "";
    }

    // This is called second to prepare the values that are accessable in the PAGE & future steps
    @Override
    public boolean prepareForStep(Map<String, SimpleCustomProperty> configurationAttributes, Map<String, String[]> requestParameters, int step){
        if (step != 1) return true;
        if(oidcCreds == null || oidcCreds.length == 0) {
            //cleanHint();
            log.trace("Delegated Authentication. fallback to general login");
            return true;
        }

        //Todo: For know until better solution
        languageBean.setLocale(Locale.ENGLISH);

        int[] targetedProvider = getTargetProvider(requestParameters);
        if(targetedProvider[0] == LOCAL_PROVIDER){
            //cleanHint();
            log.trace("Delegated Authentication. fallback to general login");
            return true;
        } else if(targetedProvider.length > 1 || targetedProvider[0] == SELECT_PROVIDER) {
            log.trace("Delegated Authentication. Using OIDC based login");
            ArrayList<Map<String, String>> providers = new ArrayList<>();
            JSONObject[] selected;
            if(targetedProvider[0] == SELECT_PROVIDER){
                log.trace("Delegated Authentication. Using all avaiable OIDC servers as selection target");
                selected = oidcCreds;
            } else {
                log.trace("Delegated Authentication. Using subset of avaiable OIDC servers as selectiontarget");
                selected = new JSONObject[targetedProvider.length];
                for(int i = 0; i < targetedProvider.length; i++){
                    selected[i] = oidcCreds[targetedProvider[i]];
                }
            }

            String nonce = UUID.randomUUID().toString();
            JSONArray states = new JSONArray(selected.length);

            for(int i = 0; i < selected.length; i++){
                log.trace("     Use OIDC server as selection target: {}", selected[i].getString("op_server"));
                String state = UUID.randomUUID().toString();
                providers.add(buildProvider(requestParameters, selected[i], nonce, state));
                states.put(state);
            }

            if(allowLocalLogin) {
                log.trace("     Use Local server as selection target");
                //Todo: nullsafety checks
                String state = requestParameters.get("state")[0];
                states.put(state);
                providers.add(buildLocal(requestParameters, requestParameters.get("nonce")[0], state));
            }

            Identity identity = CdiUtil.bean(Identity.class);
            identity.setWorkingParameter("oidc_nonce", nonce);
            identity.setWorkingParameter("oidc_state", states.toString());
            identity.setWorkingParameter("oidc_providers", providers.toArray(new Map[0]));
        } else {
            int selectedProvider = targetedProvider[0];
            log.trace("Delegated Authentication. Using preselected OIDC server as target");
            log.trace("     Use OIDC server as target: {}", oidcCreds[selectedProvider].getString("op_server"));
            String nonce = UUID.randomUUID().toString();
            String state = UUID.randomUUID().toString();
            Map<String, String> providerData = buildProvider(requestParameters, oidcCreds[selectedProvider], nonce, state);
            Identity identity = CdiUtil.bean(Identity.class);
            identity.setWorkingParameter("oidc_nonce", nonce);
            identity.setWorkingParameter("oidc_state", state);
            identity.setWorkingParameter("oidc_select", ""+selectedProvider);
            facesService.redirectToExternalURL(providerData.get("oidc_redirect_uri"));
        }
        return true;
    }

    // This is called called third to differentiate rendeing parameters from session parameters
    // Note: its further called after each getNextStep even if that function indicates no more steps
    //       finally its called at the end (I assume to remove these extra parameters from the session)
    @Override
    public List<String> getExtraParametersForStep(Map<String, SimpleCustomProperty> configurationAttributes, int step){
        //ensures these will be avaiable after we continue
        //the rest are just avaiable during PAGE rendering
        return List.of("oidc_state", "oidc_nonce", "oidc_select");
    }

    //Not declared as a helper method as it is authenticate replacement in case OIDC is disabled
    private boolean authenticateFallback(Identity identity) {
        if(!allowLocalLogin) return false;
        log.trace("Delegated Authentication. fallback to general login");

        Credentials credentials = identity.getCredentials();
        String userName = credentials.getUsername();
        String userPassword = credentials.getPassword();

        boolean res = false;
        if (StringHelper.isNotEmptyString(userName) && StringHelper.isNotEmptyString(userPassword)){
            res = authenticationService.authenticate(userName, userPassword);
        }

        UserService userService = CdiUtil.bean(UserService.class);
        //String someExistingUser = "admin";
        //testJansExtUidLookup(userService.getUser(someExistingUser));

        if(!res){
            log.info("Delegated Authentication. Local authentication failed");
        } else {
            log.info("Delegated Authentication. Local authentication suceeded");
        }
        ConymAnalytics.locAuthAttempt(userName, res);
        return res;
    }

    /*private void testJansExtUidLookup(User testUser) {
        log.debug("Executing lookup by authenticator test for user {} ",testUser.getUserId());

        UserAuthenticatorService userAuthService = CdiUtil.bean(UserAuthenticatorService.class);
        UserService userService = CdiUtil.bean(UserService.class);

        String someId = "1234567890";
        String encBindDate = userService.encodeGeneralizedTime(Date.from(Instant.now()));
        UserAuthenticator auth = userAuthService.getUserAuthenticatorById(testUser, someId);
        if(auth == null) {
            auth = userAuthService.createUserAuthenticator(someId, "test");
            userAuthService.addUserAuthenticator(testUser, auth);
        }
        testUser = userService.updateUser(testUser);
        String jansExtUid = userAuthService.formatExternalUid(someId, "test");
        User user = userService.getUserByAttribute("jansExtUid", jansExtUid);

        if(user == null) {
            log.debug("Looking up user by jansExtUid failed, user was not found");
            return;
        }

        if(testUser.equals(user)){
            log.debug("Looking up user by jansExtUid succeeded");
            return;
        }

        log.debug("Looking up user by jansExtUid resulted in an unexpected user, id was {} instead of expected {}", user,testUser);
    }*/

    private boolean authenticateWithProvider(JSONObject provider, Identity identity, Map<String, String[]> requestParameters){
        //Get the tokens
        JSONObject tokenResponse = getToken(provider,requestParameters);
        if(tokenResponse == null) {
            log.info("Delegated Authentication. Could not authenticate at target");
            ConymAnalytics.delAuthFail(provider.getString("op_server"), provider.getString("client_id"));
            return false;
        }
        String idToken = tokenResponse.optString("id_token");
        String accessToken = tokenResponse.optString("access_token");

        if(accessToken == null && idToken == null) {
            ConymAnalytics.delAuthFail(provider.getString("op_server"), provider.getString("client_id"));
            log.warn("Delegated Authentication. Could not authenticate at target due to missing tokens");
            return false;
        }

        String sub = null;

        //This deviates from original to support non OIDC targets
        // TODO: support cahnges in the rquest over config
        JSONObject tokenInfo = null;
        if(idToken != null) {
            tokenInfo = verifyIDToken(provider, identity, idToken);
            if(tokenInfo == null){
                ConymAnalytics.tokenValFail(provider.getString("op_server"), provider.getString("client_id"));
                log.warn("Delegated Authentication. Target delivers invalid ID token: {}", idToken);
                return false;
            }
            sub = tokenInfo.getString("sub");
        }

        JSONObject accessClaims = null;
        if(sub == null || sub.isEmpty() && accessToken != null) {
            accessClaims = getUserClaims(accessToken);
            if(accessClaims != null){
                sub = accessClaims.optString("sub");
            }
        }

        JSONObject userInfo = null;
        if((sub == null || sub.isEmpty()) && accessToken != null) {
            //validates access token
            userInfo = getUserInfo(provider,accessToken);
            if(userInfo == null) {
                log.warn("Delegated Authentication. Target does not support Userinfo endpoint");
            } else {
                sub = userInfo.optString("sub");
            }
        }


        //Todo: in theory we could go introspection

        if(sub == null || sub.isEmpty()) {
            ConymAnalytics.subjectIdFailed(provider.getString("op_server"), provider.getString("client_id"));
            log.warn("Delegated Authentication. Incapable of fetching sub from target");
            return false;
        }

        //Shall we cache refreshtoken &| access token to make a quick relogin on demand
        // would require that the request parameters contain sub
        // however, we would need to lock info to client otherwise it can be missused
        // I think a better approach is to issue our refresh token with a configurable duration
        //  which is max the token from the target (TODO: How needs info transfer to update token)
        User foundUser = ConymUserManager.findExtUser(provider.getString("op_server"),sub);
        if(foundUser == null) {
            Map<String,Object> attrs = collectAttrsFromSources(provider, accessToken, tokenInfo, userInfo, accessClaims);
            if(attrs == null) return false;
            foundUser = ConymUserManager.addUser(provider.getString("op_server"),sub, attrs);
        } else {
            //We could move out of the if but is here as we may do it less often in this case in the future
            //Todo: Doing this every time seems exhaustive and inneficient (in if it is necessary, but in else not)
            //      Maybe only all x time window or something like that
            //  However, as this does not happen on behaviour auths it is not that often in many use cases
            Map<String,Object> attrs = collectAttrsFromSources(provider, accessToken, tokenInfo, userInfo, accessClaims);
            if(attrs != null){
                //Todo: Doing this every time seems exhaustive and inneficient
                foundUser = ConymUserManager.updateUser(foundUser,attrs);
            }
        }

        if(foundUser == null) {
            ConymAnalytics.userEstablishmentFailed(provider.getString("op_server"), sub, provider.getString("client_id"));
            log.warn("Delegated Authentication. Failed to create or update local user");
            return false;
        }

        boolean res = authenticationService.authenticate(foundUser.getUserId());
        if(res) {
            ConymUserManager.userAuthenticated(foundUser);
            log.info("Delegated Authentication. OIDC Authentication suceeded");
        } else {
            //should not happen
            log.error("Delegated Authentication. Failed to log in remote user locally");
        }

        ConymAnalytics.delAuthAttempt(provider.getString("op_server"), sub, provider.getString("client_id"), res);
        return res;
    }

    private Map<String,Object> collectAttrsFromSources(JSONObject provider, String accessToken,  JSONObject tokenInfo, JSONObject userInfo, JSONObject accessClaims) {
        //Resolve the claims:
        Map<String,Object> attrs = new HashMap<>();
        Map<String, String> reqClaims = new HashMap<>(requiredClaims);
        Map<String, String> desClaims = new HashMap<>(desiredClaims);
        Map<String, String> optClaims = new HashMap<>(optionalClaims);

        if(tokenInfo != null){
            ConymUserManager.collectAttrsFromAllClaims(attrs, tokenInfo, reqClaims, desClaims, optClaims);
        }

        if(accessClaims == null && (!reqClaims.isEmpty() || !desClaims.isEmpty()) && accessToken != null){
            accessClaims = getUserClaims(accessToken);
        }

        if(accessClaims != null){
            ConymUserManager.collectAttrsFromAllClaims(attrs, accessClaims, reqClaims, desClaims, optClaims);
        }

        if(userInfo == null && (!reqClaims.isEmpty() || !desClaims.isEmpty()) && accessToken != null){
            userInfo = getUserInfo(provider,accessToken);
        }

        if(userInfo != null){
            ConymUserManager.collectAttrsFromAllClaims(attrs, userInfo, reqClaims, desClaims, optClaims);
        }

        if(!reqClaims.isEmpty()) {
            log.warn("Delegated Authentication. Incapable of fetching {}", reqClaims.keySet());
            log.warn("   Avaiable Source (id token): {}", tokenInfo);
            log.warn("   Avaiable Source (user info): {}", userInfo);
            return null;
        }

        return attrs;
    }

    //Todo: Move to shared ClaimManager
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

    // This is called fourth (after the target returned)
    @Override
    public boolean authenticate(Map<String, SimpleCustomProperty> configurationAttributes, Map<String, String[]> requestParameters, int step){
        log.trace("Delegated Authentication. authenticate step "+step);
        //Services
        Identity identity = CdiUtil.bean(Identity.class);
        //Regular PW Authentication fallback
        if(oidcCreds == null || oidcCreds.length == 0) {
            log.trace("Delegated Authentication. No external OIDC Configured");
            return authenticateFallback(identity);
        } else {
            if (step == 1) {
                String externalOIDCState = ServerUtil.getFirstValue(requestParameters, "state");
                //If no state avaiable, proceed for general username & password login
                //  we assume that the inline rendered login form was used
                //   in theory it could be that the remote OIDC did not set the state
                if(externalOIDCState == null) {
                    log.debug("Delegated Authentication. No OIDC Selected");
                    return authenticateFallback(identity);
                }

                Object preselectedProvider = identity.getWorkingParameter("oidc_select");
                if(preselectedProvider != null) {
                    JSONObject provider;
                    try {
                        int targetedProvider = Integer.parseUnsignedInt(preselectedProvider.toString());
                        provider = oidcCreds[targetedProvider];
                    } catch (NumberFormatException e) {
                        log.error("Delegated Authentication. oidc_select was not transfered correctly", e);
                        return false;
                    }
                    log.trace("Delegated Authentication. Using preselected provider "+provider.getString("op_server"));
                    if(!externalOIDCState.equals(identity.getWorkingParameter("oidc_state"))){
                        log.warn("Delegated Authentication. external login returned mismatching state");
                        return false;
                    }
                    log.trace("Delegated Authentication. external state verification succeded");
                    return authenticateWithProvider(provider, identity, requestParameters);
                } else {
                    log.trace("Delegated Authentication. No preselected provider, will match provider based on state");
                    JSONArray currentSessionOIDCStates = new JSONArray(identity.getWorkingParameter("oidc_state").toString());
                    for(int i = 0; i < currentSessionOIDCStates.length(); i++){
                        //State verification
                        if(externalOIDCState.equals(currentSessionOIDCStates.get(i))){
                            JSONObject provider = oidcCreds[i];
                            log.trace("Delegated Authentication. external state verification succeded for "+provider.getString("op_server"));
                            return authenticateWithProvider(provider, identity, requestParameters);
                        }
                    }
                    log.warn("Delegated Authentication. external login returned mismatching state");
                    return false;
                }
            } else {
                log.warn("Delegated Authentication. Unknown step "+step);
                return false;
            }
        }
    }

    // This is called fifth (after the first step) to see what the next step is
    @Override
    public int getNextStep(Map<String, SimpleCustomProperty> configurationAttributes, Map<String, String[]> requestParameters, int step){
        //We only have 1 step so return something out of range
        return -1;
    }

    // This is called seventh (a intervening getExtraParametersForStep) to see how many steps their are in total
    //  used to check if we are done (is getNextStep < getCountAuthenticationSteps && getNextStep > 0)
    @Override
    public int getCountAuthenticationSteps(Map<String, SimpleCustomProperty> configurationAttributes){
        return 1;
    }

    //Not called: probably is called on a manual logout, so we can logout in the external as well.
    //            if so we should overwrite this however with multiple it gets tricky we need to remember from where we came
    @Override
    public String getLogoutExternalUrl(Map<String, SimpleCustomProperty> configurationAttributes, Map<String, String[]> requestParameters){
        log.debug("Delegated Authentication. LogoutExternalUrl was called");
        return null;
    }

    //Not called: probably is called on a manual logout.
    //            Is true enough do we have todo more (especially after implementing getLogoutExternalUrl)
    @Override
    public boolean logout(Map<String, SimpleCustomProperty> configurationAttributes, Map<String, String[]> requestParameters){
        log.debug("Delegated Authentication. Logout was called");
        return true;
    }

    //------------- Helper Methods ---------------

    /*
    // Does not work
    private void cleanHint() {
        Identity identity = CdiUtil.bean(Identity.class);
        Credentials credentials = identity.getCredentials();
        String username = credentials.getUsername();
        if(".".equals(username) || "local".equals(username)
                || "*".equals(username) || "all".equals(username)
                || "default".equals(username) ) {
            credentials.setUsername("");
        }
        //Todo: shall we split host if their is an @???
    }*/

    private Integer getProviderIndex(String selectedProvider){
        for(int i = 0; i < oidcCreds.length; i++){
            if(selectedProvider.equals(oidcCreds[i].getString("op_server"))) {
                return i;
            }
        }
        return null;
    }

   private String getProviderName(int index){
        switch (index) {
            case LOCAL_PROVIDER: return "local";
            case SELECT_PROVIDER: return "select";
            default: if(oidcCreds != null && oidcCreds.length > index) {
                return oidcCreds[index].getString("op_server");
            } else {
                return "null";
            }
        }

    }

    private int[] getTargetProvider(Map<String, String[]> requestParameters) {
        if(requestParameters == null) return new int[]{defaultProvider};
        String[] provider = requestParameters.get(PROVIDER_SELECTOR_PROPERTY);
        if(provider == null || provider.length == 0) {
            log.trace("Delegated Authentication. No explicit provider specified, falling back to default "+ getProviderName(defaultProvider));
            return new int[]{defaultProvider};
        }

        if("*".equals(provider[0]) || "all".equals(provider[0].toLowerCase())){
            log.trace("Delegated Authentication. Explicit provider selection specified ");
            return new int[]{SELECT_PROVIDER};
        }

        if("default".equals(provider[0])){
            log.trace("Delegated Authentication. Explicit default provider specified ("+getProviderName(defaultProvider)+")");
            return new int[]{defaultProvider};
        }

        if("".equals(provider[0]) || ".".equals(provider[0]) || "local".equals(provider[0].toLowerCase())){
            if(allowLocalLogin) {
                log.trace("Delegated Authentication. Explicit local login specified");
                return new int[]{LOCAL_PROVIDER};
            } else {
                log.trace("Delegated Authentication. Explicit local login specified but local login is disabled, will fallback to default "+ getProviderName(defaultProvider));
                return new int[]{defaultProvider};
            }
        }

        //Todo: if more then one are provided allow for a selection Box of exactly them instead of all
        if(provider.length > 1) {
            log.trace("Delegated Authentication. Multiple providers where selected, will present all providers to user");
            int[] selectedProviders = new int[provider.length];
            for(int i = 0; i < provider.length; i++) {
                Integer sel = getProviderIndex(provider[i]);
                //Todo: Alt just ignore that one?
                if(sel == null) {
                    log.info("Delegated Authentication. Unknown provider "+provider[i]+" was requested, falling back to default "+getProviderName(defaultProvider));
                    return new int[]{defaultProvider};
                }
                selectedProviders[i] = sel;
            }
            return selectedProviders;
        }

        String selectedProvider = provider[0];
        if(selectedProvider == null) {
            log.info("Delegated Authentication. No explicit provider specified, falling back to default "+ getProviderName(defaultProvider));
            return new int[]{defaultProvider};
        }

        if(selectedProvider.contains("@")){
            selectedProvider = selectedProvider.split("@")[1];
        }

        Integer res = getProviderIndex(selectedProvider);
        if(res == null) {
            log.warn("Delegated Authentication. Unknown provider was requested: "+PROVIDER_SELECTOR_PROPERTY+"="+selectedProvider+" is not supported, falling back to default");
            return new int[]{defaultProvider};
        } else {
            log.trace("Delegated Authentication. Explicit provider specified "+ selectedProvider);
            return new int[]{res};
        }
    }

    private int[] getTargetProvider() {
        HttpServletRequest req = ServerUtil.getRequestOrNull();
        return getTargetProvider(req.getParameterMap());
    }

    private String computeScopes(Map<String, String[]> requestParameters, JSONObject provider) {
        String scopes = "";
        if(requestParameters.containsKey("scope")) {
            String[] requestedScopes =  requestParameters.get("scope");
            for(String rScope: requestedScopes){
                //mostly to support a non standard conform encoding used by rRaumobile
                String[] decodedRScopes = rScope.split( "[\\s,]+" );
                for(String rs: decodedRScopes) {
                    String reqScope = String.join(" ", rs);
                    if (!scopes.isEmpty()) {
                        scopes = scopes + " " + reqScope;
                    } else {
                        scopes = reqScope;
                    }
                }
            }
        }

        if(provider != null && provider.has("auth_scopes")){
            String atuthScopes = provider.getString("auth_scopes"); //Extra scopes added to each authentication
            if(!scopes.isEmpty()){
                scopes = scopes+" "+atuthScopes;
            } else {
                scopes = atuthScopes;
            }
        }
        return scopes;
    }

    private static Set<String> OVERWRITTEN_LOCAL_PARAMS = Set.of("login_hint", "scope", "state", "nonce");
    private Map<String, String> buildLocal(Map<String,String[]> request, String nonce, String state){
        StringBuilder redirectUrlBuilder = new StringBuilder("/jans-auth/restv1/authorize")
                .append("?login_hint=").append(".")
                .append("&scope=").append(computeScopes(request,null))
                .append("&state=").append(state)
                .append("&nonce=").append(nonce);

        //Copy existing params
        for(Map.Entry<String,String[]> origParam: request.entrySet()){
            if(OVERWRITTEN_LOCAL_PARAMS.contains(origParam.getKey())) continue;
            if(origParam.getValue().length == 0) continue;
            if(origParam.getValue().length > 1) {
                log.warn("Delegated Authentication. Local Authentication forward only supports single valued parameters, using first");
            }
            redirectUrlBuilder.append("&")
                    .append(origParam.getKey())
                    .append("=")
                    .append(origParam.getValue()[0]);
        }

        return Map.of(
                "oidc_redirect_uri", redirectUrlBuilder.toString(),
                "oidc_title", "Local Login"
        );
    }

    //Todo: does this work with pkce??
    //      if not how to pass it Through
    //      attach it to redirect_uri??
    private Map<String, String> buildProvider(Map<String, String[]> requestParameters, JSONObject provider, String nonce, String state){
        String callbackUri = baseUri+provider.getString("redirect_path");
        StringBuilder delegateBuilder = new StringBuilder(provider.getString("authorization_uri"))
                .append("?response_type=").append(provider.getString("response_type"))
                .append("&client_id=").append(provider.getString("client_id"))
                //We should make this configurable as it in non behavioural cases it may not always make sense
                .append("&prompt=").append("login")
                //We probably need some improvements here (but not sure)
                .append("&scope=").append(computeScopes(requestParameters,provider))
                .append("&state=").append(state)
                .append("&nonce=").append(nonce)
                .append("&redirect_uri=").append(callbackUri);

        String redirectUrl = delegateBuilder.toString();
        return Map.of(
                "oidc_redirect_uri", redirectUrl,
                "oidc_title", provider.getString("title")
        );
    }
    
    private JSONObject getToken(JSONObject provider, Map<String, String[]> requestParameters){
        try {
            log.trace("Delegated Authentication. Get external access token");
            String oidcCode = ServerUtil.getFirstValue(requestParameters, "code");
            String callbackUri = baseUri+provider.getString("redirect_path");
            //Todo: Switch Authentication Method
            StringBuilder tokenRequestDataBuilder = new StringBuilder()
                    .append("code=").append(URLEncoder.encode(oidcCode, StandardCharsets.UTF_8))
                    .append("&grant_type=").append("authorization_code")
                    .append("&redirect_uri=").append(URLEncoder.encode(callbackUri, StandardCharsets.UTF_8));

            Map<String, String> tokenRequestHeaders = new HashMap();
            tokenRequestHeaders.put("Content-type", "application/x-www-form-urlencoded");
            tokenRequestHeaders.put("Accept", "application/json");

            String mode = provider.optString("authorization_mode","basic");
            if("basic".equals(mode)) {
                String unencoded = new StringBuilder()
                        .append(URLEncoder.encode(provider.getString("client_id"), StandardCharsets.UTF_8))
                        .append(':')
                        .append(URLEncoder.encode(provider.getString("client_secret"), StandardCharsets.UTF_8))
                        .toString();
                tokenRequestHeaders.put("Authorization", "Basic " + BaseEncoding.base64().encode(unencoded.toString().getBytes(StandardCharsets.UTF_8)));
            } else if("post".equals(mode)) {
                tokenRequestDataBuilder
                        .append("&client_id=").append(URLEncoder.encode(provider.getString("client_id"), StandardCharsets.UTF_8))
                        .append("&client_secret=").append(URLEncoder.encode(provider.getString("client_secret"), StandardCharsets.UTF_8));
            } else if("jwt".equals(mode)) {
                log.error("Delegated Authentication. Unsupported access token authentication mode jwt");
                return null;
            } else {
                log.error("Delegated Authentication. Unknown access token authentication mode "+mode);
                return null;
            }

            String tokenRequestData = tokenRequestDataBuilder.toString();

            HttpServiceResponse resultResponse = httpService.executePost(
                    httpService.getHttpsClient(),
                    provider.getString("token_uri"),
                    null,
                    tokenRequestHeaders,
                    tokenRequestData);

            HttpResponse httpResponse = resultResponse.getHttpResponse();
            int httpResponseStatusCode = httpResponse.getStatusLine().getStatusCode();
            if (httpResponseStatusCode != 200) {
                log.warn("Delegated Authentication. get external access token failed with code: " + httpResponseStatusCode);
                return null;
            }

            byte[] responseBytes = httpService.getResponseContent(httpResponse);
            String responseString = httpService.convertEntityToString(responseBytes);
            return new JSONObject(responseString);
        } catch (Exception e){
            log.error("Delegated Authentication. Exception while fetching access token", e);
        }
        return null;
    }

    private JSONObject verifyIDToken(JSONObject provider, Identity identity, String idToken){
        //Note: We do not check signature as we recieved it directly from the issuing source over https
        //      And we trust it - this is identical to how the janssen oidc example does it
        //      Only if we got it transitively from someone else doe we need to do signature verification
        try {
            log.trace("Delegated Authentication. perform idToken check");
            Jwt jwtIdToken = Jwt.parse(idToken);
            String idTokenNonce = jwtIdToken.getClaims().getClaimAsString("nonce");
            Object currentSessionOIDCNonce = identity.getWorkingParameter("oidc_nonce");
            if (!idTokenNonce.equals(currentSessionOIDCNonce)) {
                log.warn("Delegated Authentication. mismatching idToken nonce: Expected {}, but received {}", currentSessionOIDCNonce, idTokenNonce);
                return null;
            }
            String idTokenAud = jwtIdToken.getClaims().getClaimAsString("aud");
            if (!idTokenAud.equals(provider.getString("client_id"))) {
                log.warn("Delegated Authentication. mismatching idToken audience:  Expected {}, but received {}", provider.getString("client_id"), idTokenAud);
                return null;
            }

            long idTokenExp = jwtIdToken.getClaims().getClaimAsLong("exp");
            long now = Instant.now().getEpochSecond();
            boolean hasExpired = idTokenExp < now;
            if(idTokenExp < now) {
                log.info("Delegated Authentication. idToken is expired");
                return null;
            }

            log.trace("Delegated Authentication. idToken verification sucessfull");
            return jwtIdToken.getClaims().toJsonObject();
        } catch (Exception e){
            log.error("Delegated Authentication. Exception while verifying idToken", e);
        }
        return null;
    }

    private JSONObject getUserInfo(JSONObject provider, String accessToken){
        try{
            Map<String, String> tokenRequestHeaders = Map.of(
                    "Authorization", "Bearer "+accessToken,
                    "Accept", "application/json"
            );

            //Todo: if no user info endpoint is registered try the token introspection endpoint
            HttpServiceResponse resultResponse = httpService.executeGet(
                    httpService.getHttpsClient(),
                    provider.getString("userinfo_uri"),
                    tokenRequestHeaders);

            HttpResponse httpResponse = resultResponse.getHttpResponse();
            int httpResponseStatusCode = httpResponse.getStatusLine().getStatusCode();
            if(httpResponseStatusCode != 200){
                log.warn("Delegated Authentication. get external user info failed with code: " + httpResponseStatusCode);
                return null;
            }

            byte[] responseBytes = httpService.getResponseContent(httpResponse);
            String responseString = httpService.convertEntityToString(responseBytes);
            return new JSONObject(responseString);
        } catch (Exception e){
            log.error("Delegated Authentication. Exception while fetching user info", e);
        }
        return null;
    }
    private JSONObject getUserClaims(String accessToken){
        //we trust as we got from trusted source - like in IdToken (state is already checked)
        Jwt accessJwt = Jwt.parseSilently(accessToken);
        if(accessJwt == null) return null;
        try {
            return accessJwt.getClaims().toJsonObject();
        } catch (InvalidJwtException e) {
            return null;
        }
    }
}
