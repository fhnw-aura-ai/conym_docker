import io.jans.model.SimpleCustomProperty;
import io.jans.model.custom.script.model.CustomScript;
import io.jans.service.custom.script.CustomScriptManager;
import io.jans.model.custom.script.type.scope.DynamicScopeType;
import io.jans.as.server.service.external.context.DynamicScopeExternalContext;
import io.jans.as.server.model.common.IAuthorizationGrant;
import io.jans.as.model.token.JsonWebResponse;
import io.jans.as.model.configuration.AppConfiguration;
import io.jans.service.cdi.util.CdiUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.*;

import ch.fhnw.imvs.ai.aura.ConymClaimManager;

public class ConymUserInfo implements DynamicScopeType {

    //Todo: does this request entropy each time used or once on init and then use a prng?
    private static final Logger log = LoggerFactory.getLogger(CustomScriptManager.class);

    private AppConfiguration appConfig = null;

    @Override
    public boolean init(Map<String, SimpleCustomProperty> configurationAttributes) {
        log.info("ConymUserInfo. Initializing...");
        appConfig = CdiUtil.bean(AppConfiguration.class);
        if(!ConymClaimManager.init(appConfig)) return false;
        log.info("ConymUserInfo. Initialized");
        return true;
    }

    @Override
    public boolean init(CustomScript customScript, Map<String, SimpleCustomProperty> configurationAttributes) {
        return init(configurationAttributes);
    }

    @Override
    public boolean destroy(Map<String, SimpleCustomProperty> configurationAttributes) {
        log.info("ConymUserInfo. Destroying...");
        return true;
    }

    @Override
    public int getApiVersion() {
        return 11;
    }

    @Override
    public boolean update(Object dynamicScopeContext, Map<String, SimpleCustomProperty> configurationAttributes) {
        DynamicScopeExternalContext dynamicContext = (DynamicScopeExternalContext) dynamicScopeContext;
        IAuthorizationGrant grant = dynamicContext.getAuthorizationGrant();
        JsonWebResponse jwt = dynamicContext.getJsonWebResponse();
        String sub = ConymClaimManager.modifyClaims(grant.getUser(), grant.getClient(), grant.getScopes(), jwt.getClaims());
        return sub != null;
    }

    @Override
    public List<String> getSupportedClaims(Map<String, SimpleCustomProperty> configurationAttributes) {
        List<String> extra =  ConymClaimManager.supportedClaims(true); //Not sure if the true is necessary
        List<String> result = new ArrayList<String>(extra.size()+2);
        result.add("sub");
        result.add("provider");
        result.addAll(extra);
        return result;
    }
}
