import io.jans.model.SimpleCustomProperty;
import io.jans.model.custom.script.model.CustomScript;
import io.jans.model.custom.script.type.authz.ConsentGatheringType;
import io.jans.service.custom.script.CustomScriptManager;
import io.jans.as.server.service.external.context.ConsentGatheringContext;
import io.jans.as.server.authorize.ws.rs.ConsentGathererService;
import io.jans.as.model.configuration.AppConfiguration;
import io.jans.as.persistence.model.Scope;
import io.jans.service.cdi.util.CdiUtil;
import io.jans.as.common.model.common.User;

import org.json.JSONObject;
import org.json.JSONArray;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.fhnw.imvs.ai.aura.ConymUserManager;


public class ConsentGathering implements ConsentGatheringType {

    private static final Logger log = LoggerFactory.getLogger(CustomScriptManager.class);

    private ConsentGathererService gatherer = null;
    private AppConfiguration appConfig = null;
    private final Map<String, Set<String>> consentExemptProviderScopes = new HashMap();

    @Override
    public boolean init(Map<String, SimpleCustomProperty> configurationAttributes) {
        log.info("Consent gathering. Initializing...");
        appConfig = CdiUtil.bean(AppConfiguration.class);
        gatherer = CdiUtil.bean(ConsentGathererService.class);
        if(!ConymUserManager.init(appConfig)) return false;
        if (configurationAttributes.containsKey("oidc_cred_files")) {
            log.info("Consent gathering. Using OIDC Config File: "+configurationAttributes.get("oidc_cred_files").getValue2());
            JSONArray oidcCredsFiles = new JSONArray(configurationAttributes.get("oidc_cred_files").getValue2());
            for(int i = 0; i < oidcCredsFiles.length(); i++){
                String oidcCredsFile = oidcCredsFiles.get(i).toString();
                try {
                    JSONObject oidcCred = new JSONObject(new String(Files.readAllBytes(Paths.get(oidcCredsFile))));
                    String op = oidcCred.getString("op_server");
                    if(oidcCred.has("consent_excempt_scopes")) {
                        JSONArray scopes = oidcCred.getJSONArray("consent_excempt_scopes");
                        Set<String> exemptScopes = new HashSet();
                        for(int j = 0; j < scopes.length(); j++ ){
                            exemptScopes.add(scopes.get(j).toString());
                        }
                        consentExemptProviderScopes.put(op,exemptScopes);
                        log.info("Consent gathering. Enabled consent exemptions for following OIDC Provider: "+op+" and scopes: "+exemptScopes);
                    } else {
                        log.info("Consent gathering. No consent exemptions for following OIDC Provider: "+op+" are configured");
                        log.info("Consent gathering. : "+oidcCred);

                    }
                } catch (Exception e){
                    log.error("Consent gathering. Reading Inbound OIDC failed",e);
                    return false;
                }
            }
        }
        log.info("Consent gathering. Initialized");
        return true;
    }

    @Override
    public boolean init(CustomScript customScript, Map<String, SimpleCustomProperty> configurationAttributes) {
        return init(configurationAttributes);
    }

    @Override
    public boolean destroy(Map<String, SimpleCustomProperty> configurationAttributes) {
        log.info("Consent gathering. Destroying...");
        log.info("Consent gathering. Destroyed.");
        return true;
    }

    @Override
    public int getApiVersion() {
        return 11;
    }

    private boolean isExempt(ConsentGatheringContext gatheringContext) {
        User user = gatheringContext.getUser();
        if(user == null)  return false;
        String provider = ConymUserManager.getProvider(user);
        if(provider == null) return false;
        if(!consentExemptProviderScopes.containsKey(provider)) return false;
        Set<String> exemptions = consentExemptProviderScopes.get(provider);
        List<Scope> scopes = gatherer.getScopes();
        for(Scope s: scopes) {
            if(!exemptions.contains(s.getId())) return false;
        }
        return true;
    }

    @Override
    public boolean authorize(int step, Object consentContext) {
        ConsentGatheringContext gatheringContext = (ConsentGatheringContext) consentContext;
        String[] allowButton = gatheringContext.getRequestParameters().get("authorizeForm:allowButton");
        if (step == 1) {
            if (allowButton != null && allowButton.length > 0) {
                log.info("Consent gathering. Authorization Suceeded");
                return true;
            }

            if(isExempt(gatheringContext)) {
                log.info("Consent gathering. Delegated Provider was Excempt from Authorization");
                return true;
            }
            log.info("Consent gathering. Authorization Failed");
        }
        return false;
    }

    @Override
    public int getNextStep(int step, Object consentContext) {
        return -1;
    }

    @Override
    public boolean prepareForStep(int step, Object consentContext) {
        ConsentGatheringContext gatheringContext = (ConsentGatheringContext) consentContext;
        if (!gatheringContext.isAuthenticated()) {
            log.info("User is not authenticated. Aborting authorization flow...");
            return false;
        }
        return true;
    }

    @Override
    public int getStepsCount(Object consentContext) {
        return 1;
    }
    @Override
    public String getPageForStep(int step, Object consentContext) {
        if(step != 1) return "";
        ConsentGatheringContext gatheringContext = (ConsentGatheringContext) consentContext;
        if(isExempt(gatheringContext)) return "/authz/skip.xhtml";
        return "/authz/authorize.xhtml";
    }
}
