import java.util.*;
import java.lang.Math;

import io.jans.model.SimpleCustomProperty;
import io.jans.model.custom.script.model.CustomScript;
import io.jans.model.custom.script.type.postauthn.PostAuthnType;
import io.jans.service.custom.script.CustomScriptManager;
import io.jans.as.server.service.external.context.ExternalPostAuthnContext;
import io.jans.as.server.service.SectorIdentifierService;
import io.jans.as.server.authorize.ws.rs.AuthzRequest;
import io.jans.as.model.configuration.AppConfiguration;
import io.jans.as.common.model.common.User;
import io.jans.as.common.model.registration.Client;
import io.jans.service.cdi.util.CdiUtil;
import io.jans.as.common.model.session.SessionId;

import ch.fhnw.imvs.ai.aura.ConymDeviceManager;
import ch.fhnw.imvs.ai.aura.ConymCAManager;
import ch.fhnw.imvs.ai.aura.ConymAnalytics;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PostAuthn implements PostAuthnType {
    private static final Logger log = LoggerFactory.getLogger(CustomScriptManager.class);
    private AppConfiguration appConfig = null;
    private SectorIdentifierService sectorIdentifierService = null;
    private long freshLoginThresholdMs = 15*1000;

    @Override
    public boolean init(Map<String, SimpleCustomProperty> configurationAttributes) {
        log.info("Post Authentication. Initializing...");

        appConfig = CdiUtil.bean(AppConfiguration.class);
        sectorIdentifierService = CdiUtil.bean(SectorIdentifierService.class);

        if(!ConymDeviceManager.init(appConfig)) return false;
        if(!ConymCAManager.init(appConfig)) return false;
        if(!ConymAnalytics.init(appConfig)) return false;
        if (configurationAttributes.containsKey("fresh_auth_timeout")) {
            String timeout = configurationAttributes.get("fresh_auth_timeout").getValue2();
            try {
                freshLoginThresholdMs = Long.parseLong(timeout);
                log.info("Post Authentication. Using configured fresh authentication timeout of {}ms", freshLoginThresholdMs);
            } catch (NumberFormatException e) {
                log.error("Post Authentication. Configured fresh authentication timeout {} is not a long", timeout);
                return false;
            }
        } else {
            log.info("Post Authentication. Using default fresh authentication timeout of {}ms", freshLoginThresholdMs);
        }


        log.info("Post Authentication. Initialized.");
        return true;
    }

    @Override
    public boolean init(CustomScript customScript, Map<String, SimpleCustomProperty> configurationAttributes) {
        return init(configurationAttributes);
    }

    @Override
    public boolean destroy(Map<String, SimpleCustomProperty> configurationAttributes) {
        log.info("Post Authentication. Destroying...");
        log.info("Post Authentication. Destroyed.");
        return true;
    }

    @Override
    public int getApiVersion() {
        return 11;
    }

    @Override
    public boolean forceReAuthentication(Object context) {
        ExternalPostAuthnContext paContext = (ExternalPostAuthnContext) context;
        SessionId ses = paContext.getSession();
        //When was last auth?: A new fresh auth counts as good session
        //  Otherwise we could never log in when CA says no even with credentials
        //  It would immediately get cancled
        Date startDate = ses.getAuthenticationTime();
        long now = System.currentTimeMillis();
        if(startDate != null && (now - startDate.getTime()) < freshLoginThresholdMs){
            log.trace("Post Authentication. ReAuthentication was skipped as last authentication was recent");
            return false;
        } else {
            long diff = now - startDate.getTime();
            log.trace("Post Authentication. ReAuthentication required as last authentication was {}ms ago which is more than threshold of {}ms", diff, freshLoginThresholdMs);
        }

        User user = ses.getUser();
        if(user == null) {
            log.warn("Post Authentication. No user was assosiated with session - ReAuthentication requested");
            return true;
        }

        Client requestingClient = paContext.getClient();
        if(requestingClient == null) {
            log.warn("Post Authentication. No client was assosiated with user - ReAuthentication requested");
            return true;
        }

        String sub = sectorIdentifierService.getSub(requestingClient, user, false);
        if(sub == null) {
            log.warn("Post Authentication. Invalid user was assosiated with session (had no sub) - ReAuthentication requested");
            return true;
        }

        String[] scopes = paContext.getAuthzRequest().getScope().split("\\s+");

        String device = ConymDeviceManager.getDeviceId(user);

        if(device == null) {
            log.info("Post Authentication. User is not in a device locked session - No ReAuthentication necessary");
            return false;
        }

        ConymAnalytics.caSessionReAuth(sub, device, requestingClient.getClientId(), scopes);
        if(ConymCAManager.doCAAuth(scopes, sub, device, requestingClient.getClientId())) {
            log.info("Post Authentication. User still meets threshold - No ReAuthentication necessary");
            return false;
        } else {
            log.info("Post Authentication. User does no longer meet threshold - ReAuthentication requested");
            return true;
        }
    }

    @Override
    public boolean forceAuthorization(Object context) {
        return false;
    }

}
