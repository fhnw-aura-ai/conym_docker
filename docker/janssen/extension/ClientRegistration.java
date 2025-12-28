import io.jans.as.common.model.registration.Client;
import io.jans.as.server.service.external.context.DynamicClientRegistrationContext;
import io.jans.model.SimpleCustomProperty;
import io.jans.model.custom.script.model.CustomScript;
import io.jans.model.custom.script.type.client.ClientRegistrationType;
import io.jans.service.custom.script.CustomScriptManager;
import io.jans.as.model.configuration.AppConfiguration;
import io.jans.service.cdi.util.CdiUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.fhnw.imvs.ai.aura.ConymClientManager;
import java.util.*;

public class ClientRegistration implements ClientRegistrationType {
    private static final Logger log = LoggerFactory.getLogger(CustomScriptManager.class);

    private AppConfiguration appConfig = null;

    @Override
    public boolean init(Map<String, SimpleCustomProperty> configurationAttributes) {
        log.info("Client registration. Initializing ...");
        appConfig = CdiUtil.bean(AppConfiguration.class);
        if(!ConymClientManager.init(appConfig)) return false;
        log.info("Client registration. Initialized.");
        String enabled = System.getenv("JANSSEN_DYNAMIC_CLIENTS_ENABLED");
        if(enabled != null && !("true".equals(enabled))) {
            log.info("Client registration. Dynamic client registration is disabled");
        }
        return true;
    }
    @Override
    public boolean init(CustomScript customScript, Map<String, SimpleCustomProperty> configurationAttributes) {
        return init(configurationAttributes);
    }
    @Override
    public boolean destroy(Map<String, SimpleCustomProperty> configurationAttributes) {
        log.info("Client registration. Destroy.");
        return true;
    }

    @Override
    public int getApiVersion() {
        return 11;
    }

    @Override
    public boolean createClient(Object context) {
        log.trace("Client registration. CreateClient method called");
        DynamicClientRegistrationContext regContext = (DynamicClientRegistrationContext) context;
        String enabled = System.getenv("JANSSEN_DYNAMIC_CLIENTS_ENABLED");
        if(enabled != null) {
            switch (enabled) {
                case "true":
                case "internal":
                case "public":
                    return ConymClientManager.fillClient(regContext.getClient());
                case "false":
                case "private":
                default:
                    log.warn("Client registration. Dynamic client registration was attempted and rejected");
                    return false;
            }
        } else {
            //Default is on for now
            return ConymClientManager.fillClient(regContext.getClient());
        }
    }

    @Override
    public boolean updateClient(Object context) {
        return true;
    }

    // This method needs to be overridden if client is providing an SSA with HMAC
    @Override
    public String getSoftwareStatementHmacSecret(Object context) {
        return "";
    }

    // This method needs to be overridden if client is providing an SSA and RS256 validation
    @Override
    public String getSoftwareStatementJwks(Object context) {
        return "";
    }

    @Override
    public String getDcrHmacSecret(Object o) {
        return "";
    }

    @Override
    public String getDcrJwks(Object o) {
        return "";
    }

    @Override
    public boolean isCertValidForClient(Object o, Object o1) {
        return false;
    }

    @Override
    public boolean modifyPutResponse(Object responseAsJsonObject, Object executionContext) {
        return true;
    }

    @Override
    public boolean modifyReadResponse(Object responseAsJsonObject, Object executionContext) {
        return true;
    }

    @Override
    public boolean modifyPostResponse(Object responseAsJsonObject, Object executionContext) {
        return true;
    }
}
