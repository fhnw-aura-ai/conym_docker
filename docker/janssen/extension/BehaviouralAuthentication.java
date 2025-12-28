import io.jans.as.common.model.common.User;
import io.jans.as.common.model.registration.Client;
import io.jans.as.server.service.SectorIdentifierService;
import io.jans.as.server.service.SessionIdService;
import io.jans.as.common.model.session.SessionId;
import io.jans.as.server.service.external.context.ExternalScriptContext;
import io.jans.model.SimpleCustomProperty;
import io.jans.model.custom.script.model.CustomScript;
import io.jans.model.custom.script.type.authzchallenge.AuthorizationChallengeType;
import io.jans.as.model.configuration.AppConfiguration;
import io.jans.as.server.service.AuthenticationService;
import io.jans.service.cdi.util.CdiUtil;
import io.jans.service.custom.script.CustomScriptManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import ch.fhnw.imvs.ai.aura.ConymUserManager;
import ch.fhnw.imvs.ai.aura.ConymDeviceManager;
import ch.fhnw.imvs.ai.aura.ConymCAManager;
import ch.fhnw.imvs.ai.aura.ConymAnalytics;

//Todo: Rename, it can do general contionous (not just behavioural)
//      It can even do permanent device locking
//      Will also require renaming some parameters -- source must be part of template not placeholder
public class BehaviouralAuthentication implements AuthorizationChallengeType {

    public static final String USER_PARAMETER = "user";
    public static final String MODE_PARAMETER = "mode";


    private static final Logger log = LoggerFactory.getLogger(CustomScriptManager.class);

    private static final String PARAM_MODE = "param";
    private static final String PARAM_MODE_DEFAULT_SEP = ":";

    private static final Set<String> SUPPORTED_MODES = Set.of("check","enforce", PARAM_MODE);

    private String mode = "check";
    private String fallbackMode = "check";


    private AppConfiguration appConfig = null;
    private SectorIdentifierService secService = null;
    private AuthenticationService authenticationService = null;
    private SessionIdService sessionService = null;

    @Override
    public boolean init(Map<String, SimpleCustomProperty> configurationAttributes) {
        log.info("Behavioural Authentication. Initializing...");

        appConfig = CdiUtil.bean(AppConfiguration.class);
        secService = CdiUtil.bean(SectorIdentifierService.class);
        authenticationService = CdiUtil.bean(AuthenticationService.class);
        sessionService = CdiUtil.bean(SessionIdService.class);

        if(!ConymUserManager.init(appConfig)) return false;
        if(!ConymDeviceManager.init(appConfig)) return false;
        if(!ConymCAManager.init(appConfig)) return false;
        if(!ConymAnalytics.init(appConfig)) return false;

        if (configurationAttributes.containsKey("mode")) {
            String cMode = configurationAttributes.get("mode").getValue2();
            if(cMode.startsWith(PARAM_MODE)){
                String[] splitted = cMode.split(PARAM_MODE_DEFAULT_SEP);
                if(splitted.length > 2) {
                    log.error("Behavioural Authentication. Mode {} has illegal format, param only supports one default",cMode);
                    return false;
                } else if(splitted.length == 1){
                    mode = splitted[0];
                    log.info("Behavioural Authentication. No fallback for param mode provided, using default fallback {}",fallbackMode);
                } else {
                    mode = splitted[0];
                    String fallback = splitted[1];
                    if(SUPPORTED_MODES.contains(fallback) && !PARAM_MODE.equals(fallback)){
                        fallbackMode = fallback;
                    } else {
                        log.error("Behavioural Authentication. Mode {} is not supported",cMode);
                        return false;
                    }
                }
            } else if(SUPPORTED_MODES.contains(cMode)){
                mode = cMode;
                //not really necessary
                if(!PARAM_MODE.equals(cMode)){
                    fallbackMode = cMode;
                }
            } else {
                log.warn("Behavioural Authentication. Mode {} not supported fallingt back to default mode {}, supported modes are {}",cMode,mode,SUPPORTED_MODES);
            }
        } else {
            log.info("Behavioural Authentication. No Mode configured falling back to default mode {}",mode);
        }


        log.info("Behavioural Authentication. Initialized.");
        return true;
    }

    @Override
    public boolean init(CustomScript customScript, Map<String, SimpleCustomProperty> configurationAttributes) {
        return init(configurationAttributes);
    }

    @Override
    public boolean destroy(Map<String, SimpleCustomProperty> configurationAttributes) {
        log.info("Behavioural Authentication. Destroyed Java custom script.");
        return true;
    }

    @Override
    public int getApiVersion() {
        return 11;
    }

    //@Override
    public void prepareAuthzRequest(Object scriptContext){
        return;
    }

    private boolean behaviouralAuth(ExternalScriptContext context){
        //Todo: Make global or even better configurable
        Client requestingClient = context.getExecutionContext().getClient();
        String deviceId = ConymDeviceManager.getDeviceIdIfPresent(context.getHttpRequest());
        if(deviceId == null) {
            ConymAnalytics.deviceIdFailed(requestingClient.getClientId());
            log.info("Behavioural Authentication. Device authentication failed");
            return false;
        } else {
            log.trace("Behavioural Authentication. Device authenticated as {}", deviceId);
        }

        User user = ConymDeviceManager.getBoundUser(deviceId, requestingClient.getClientId());
        if(user == null){
            ConymAnalytics.userIdFailed(deviceId, requestingClient.getClientId());
            log.info("Behavioural Authentication. Identified device is not assosiated with a user (last login was to long ago/never)");
            return false;
        } else {
            log.trace("Behavioural Authentication. Bound user identified as {}", user.getUserId());
        }

        String sub = secService.getSub(requestingClient, user, false);

        String expectedUserId = context.getHttpRequest().getParameter(USER_PARAMETER);
        if(expectedUserId != null && !sub.equals(expectedUserId)){
            ConymAnalytics.userIdMismatch(sub, deviceId, requestingClient.getClientId(), expectedUserId);
            log.info("Behavioural Authentication. Identified device is not assosiated with requested user");
            return false;
        }

        //Todo: Make Behavioural Optional and support client cert locking only (as alternative to refresh token)
        //      Would requiring renaming this class / making it more modular alla configurable second opinion
        String[] scopes = context.getAuthzRequest().getScope().split("\\s+");
        if(!ConymCAManager.doCAAuth(scopes, sub, deviceId, requestingClient.getClientId())){
            log.info("Behavioural Authentication. Failed - Not confident enough");
            return false;
        }


        final boolean ok = authenticationService.authenticate(user.getUserId());
        if (ok) {
            ConymUserManager.userAuthenticated(user);
            context.getExecutionContext().setUser(user); // <- IMPORTANT : without user set, user relation will not be associated with token
            log.info("Behavioural Authentication. User {} is authenticated successfully.", user.getUserId()); //Todo: use global id here
            return true;
        }

        // 3. not ok -> set error which explains what is wrong and return false
        ConymAnalytics.postCaAuthFailed(sub, deviceId, requestingClient.getClientId());
        log.info("Behavioural Authentication. Failed to authenticate user {}. Please check user attribute", user.getUserId());
        return false;
    }

    @Override
    public boolean authorize(Object scriptContext) {
        ExternalScriptContext context = (ExternalScriptContext) scriptContext;
        boolean res = behaviouralAuth(context);
        if(res) return true;
        String usedMode = mode;
        String passedParam = context.getHttpRequest().getParameter(MODE_PARAMETER);
        if(PARAM_MODE.equals(usedMode)) {
            if(passedParam != null) {
                if(SUPPORTED_MODES.contains(passedParam) && !PARAM_MODE.equals(passedParam)){
                    usedMode = passedParam;
                } else {
                    log.trace("Behavioural Authentication. Specified param {} not supported, falling back to default {}",passedParam, fallbackMode);
                    usedMode = fallbackMode;
                }
            } else {
                usedMode = fallbackMode;
            }
        } else if(passedParam != null){
            log.warn("Behavioural Authentication. Mode is fixed, parameter {} was ignored",passedParam);
        }

        if ("enforce".equals(mode)) {
            SessionId session = context.getExecutionContext().getSessionId();
            if(session != null) {
                sessionService.reinitLogin(session, true);
            } else {
                log.warn("Behavioural Authentication. Could not identify session for enforced logout");
            }
        }
        return false;
    }

    //  Jnssen had a strange interface addition - so without override it works independent on when the janssen image was loaded
    //@Override
    public Map<String, String> getAuthenticationMethodClaims(Object context){
        return Map.of();
    }

}