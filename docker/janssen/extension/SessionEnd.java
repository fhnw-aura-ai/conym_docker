import io.jans.as.common.model.registration.Client;
import io.jans.as.server.service.external.context.DynamicClientRegistrationContext;
import io.jans.model.SimpleCustomProperty;
import io.jans.model.custom.script.model.CustomScript;
import io.jans.model.custom.script.type.logout.EndSessionType;
import io.jans.service.custom.script.CustomScriptManager;
import io.jans.as.model.configuration.AppConfiguration;
import io.jans.service.cdi.util.CdiUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.fhnw.imvs.ai.aura.ConymClientManager;
import java.util.*;

public class SessionEnd implements EndSessionType  {
    private static final Logger log = LoggerFactory.getLogger(CustomScriptManager.class);

    private AppConfiguration appConfig = null;

    @Override
    public boolean init(Map<String, SimpleCustomProperty> configurationAttributes) {
        log.info("Session Termination. Initializing ...");
        appConfig = CdiUtil.bean(AppConfiguration.class);

        log.info("Session Termination.  Initialized.");
        return true;
    }
    @Override
    public boolean init(CustomScript customScript, Map<String, SimpleCustomProperty> configurationAttributes) {
        return init(configurationAttributes);
    }
    @Override
    public boolean destroy(Map<String, SimpleCustomProperty> configurationAttributes) {
        log.info("Session Termination. Destroy.");
        return true;
    }

    @Override
    public String getFrontchannelHtml(Object context){
        log.debug("Session Termination. FrontChannel Requested");
        return "";
    }

    @Override
    public int getApiVersion() {
        return 11;
    }

}
