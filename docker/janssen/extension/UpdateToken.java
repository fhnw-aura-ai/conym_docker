import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import io.jans.model.SimpleCustomProperty;
import io.jans.model.custom.script.model.CustomScript;
import io.jans.model.custom.script.type.token.UpdateTokenType;
import io.jans.service.custom.script.CustomScriptManager;
import io.jans.as.server.service.external.context.ExternalUpdateTokenContext;
import io.jans.as.server.model.common.AuthorizationGrant;
import io.jans.as.model.configuration.AppConfiguration;

import io.jans.as.server.model.common.AccessToken;
import io.jans.as.model.jwt.JwtClaims;
import io.jans.as.model.token.JsonWebResponse;
import io.jans.as.server.service.ScopeService;
import io.jans.as.persistence.model.Scope;
import io.jans.as.common.model.registration.Client;
import io.jans.service.cdi.util.CdiUtil;
import io.jans.as.common.model.common.User;
import io.jans.as.model.common.SubjectType;

import org.json.JSONObject;
import org.json.JSONArray;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.fhnw.imvs.ai.aura.ConymClaimManager;
import ch.fhnw.imvs.ai.aura.ConymDeviceManager;
import ch.fhnw.imvs.ai.aura.ConymUserManager;

public class UpdateToken implements UpdateTokenType {

    private static final Logger log = LoggerFactory.getLogger(CustomScriptManager.class);

    private static final String CONYM_SCOPE = "conym";

    private JSONObject static_lifetimes = null;
    private JSONObject spontaneous_lifetimes = null;

    private int scopeLifetimeFallback = 300;

    private ScopeService scopeService = null;
    private AppConfiguration appConfig = null;

    //Todo: Overwrite for systems where only the idToken is requested
    //      Note: Proacc only supports Access token at the moment, not idTokens
    //            Would be complicated anyway
    //            And not needed a OIDC app simply sets accepted issuer and is fine
    private boolean isIdTokenBinding = false;

    @Override
    public boolean init(Map<String, SimpleCustomProperty> configurationAttributes) {
        log.info("UpdateToken. Initializing ...");
        scopeService = CdiUtil.bean(ScopeService.class);
        appConfig = CdiUtil.bean(AppConfiguration.class);

        if(!ConymClaimManager.init(appConfig)) return false;
        if(!ConymDeviceManager.init(appConfig)) return false;
        if(!ConymUserManager.init(appConfig)) return false;

        if (configurationAttributes.containsKey("scope_lifetimes")) {
            log.info("Using Scope Lifetime Config: "+configurationAttributes.get("scope_lifetimes").getValue2());
            static_lifetimes = new JSONObject(configurationAttributes.get("scope_lifetimes").getValue2());
        } else {
            log.info("Update Token. Scope Lifetimes not found - fallback to "+scopeLifetimeFallback+" seconds");
        }

        if (configurationAttributes.containsKey("spont_scope_lifetimes")) {
            log.info("Using Spontaneous Scope Lifetime Config: "+configurationAttributes.get("spont_scope_lifetimes").getValue2());
            spontaneous_lifetimes = new JSONObject(configurationAttributes.get("spont_scope_lifetimes").getValue2());
        } else {
            log.info("Update Token. Spontaneous Scope Lifetimes not found - fallback to "+scopeLifetimeFallback+" seconds");
        }

        log.info("Update Token. Initialized.");
        return true;
    }

    @Override
    public boolean init(CustomScript customScript, Map<String, SimpleCustomProperty> configurationAttributes) {
        return init(configurationAttributes);
    }

    @Override
    public boolean destroy(Map<String, SimpleCustomProperty> configurationAttributes) {
        log.info("Update Token. Destroyed Java Custom Script");
        return true;
    }

    @Override
    public int getApiVersion() {
        return 11;
    }

	@Override
    public boolean modifyIdToken(Object jsonWebResponse, Object tokenContext){
        ExternalUpdateTokenContext context = (ExternalUpdateTokenContext) tokenContext;
        JsonWebResponse jwtResp = (JsonWebResponse)jsonWebResponse;
        AuthorizationGrant grant = context.getGrant();
        String sub = ConymClaimManager.modifyClaims(grant.getUser(), grant.getClient(), grant.getScopes(), jwtResp.getClaims());
        if(sub == null) {
            log.info("Update Token. No Sub found - Id token denied");
            return false;
        }
        if(isIdTokenBinding){
            ConymDeviceManager.bindUserToDeviceIfPresent(context.getHttpRequest(), grant.getClient(), grant.getUser());
        }
        return true;
    }

    @Override
    public boolean modifyAccessToken(Object accessToken, Object tokenContext){
        ExternalUpdateTokenContext context = (ExternalUpdateTokenContext) tokenContext;
        AuthorizationGrant grant = context.getGrant();
        Set<String> scopes = new HashSet(grant.getScopes());
        JwtClaims claims = context.getClaims();
        String sub;
        if(claims != null) {
            //it is a jwt token
            sub = ConymClaimManager.modifyClaims(grant.getUser(),grant.getClient(), scopes, claims);
        } else {
            //it not a jwt token - we still need sub
            sub = ConymClaimManager.getSubClaim(grant.getUser(),grant.getClient(), scopes);
        }
        if(sub == null) {
            log.info("Update Token. No Sub found - Access token denied");
            return false;
        }
        boolean res = injectAndVerifyScopes(context, scopes);
        if(!res) {
            //Find out why this happens on refresh tokens sometimes and if it has consequences
            log.warn("Update Token. Scope Injection failed - Access token denied");
        }
        context.overwriteAccessTokenScopes((AccessToken)accessToken, scopes);
        //Is needed for reverse lookup in token exchange (as token exchange only works with access tokens not id, it is only needed here)
        User user = ConymUserManager.registerUserSub(grant.getUser(), grant.getClient(), sub);
        ConymDeviceManager.bindUserToDeviceIfPresent(context.getHttpRequest(), grant.getClient(), user);
        return true;
    }

	@Override
    public boolean modifyRefreshToken(Object refreshToken, Object tokenContext){
        ExternalUpdateTokenContext context = (ExternalUpdateTokenContext) tokenContext;

        return true;
	}

    //Todo: make name of pseudonym scope configurable
    private boolean injectAndVerifyScopes(ExternalUpdateTokenContext context, Set<String> scopes) {
        //Add a scope that ensures that the DynamicScope Scripts run
        Client client = context.getClient();
        SubjectType subT = client.getSubjectType();

        String conymScope = scopeService.getScopeById(CONYM_SCOPE).getDn();
        boolean conymScopeSupported = Arrays.stream(client.getScopes()).anyMatch(conymScope::equals);
        if(conymScopeSupported) {
            log.trace("Update Token. Added conym scope to token");
            //scopes.add(CONYM_SCOPE);
        } else {
            //For now we always add - figure out why the client spontaneously loose conym scope
            log.warn("Update Token. Client Lacks "+CONYM_SCOPE+" scope");
        }
        //For now we always add - figure out why the client spontaneously loose conym scope
        scopes.add(CONYM_SCOPE);
        return conymScopeSupported;
    }

    private int extractLifetime(String scope) {
        for(String key : spontaneous_lifetimes.keySet()){
            //Todo: For performance reason better compile Pattern once and cache the result -- also allows to detect illegal pattern during init
            Pattern p = Pattern.compile(key);
            Matcher m = p.matcher(scope);
            if(m.find()){
                try {
                    int level = Integer.parseInt(m.group(1));
                    JSONArray arr = spontaneous_lifetimes.getJSONArray(key);
                    //Checks that is in defined range: First 2 elems specify lower & upper bound
                    if(level >= arr.getInt(0) && level <= arr.getInt(1)) {
                        //computes the polynom: c0 + c1*l + c2*l^2 + c3*l^3, ...
                        //  where ci = arr.getInt(i+2)
                        int base = 1;
                        double res = 0;
                        for(int i = 2; i < arr.length(); i++){
                            res += arr.getDouble(i)*base;
                            base = base*level;
                        }
                        //We only return natural numbers but allow intermediary numbers to be more precise
                        return (int)res;
                    }
                } catch (Exception ignored){}
            }
        }
        return 0;
    }

    private int getLifetimeFromScopes(ExternalUpdateTokenContext tokenContext) {
        if(static_lifetimes == null && spontaneous_lifetimes == null) {
            log.info("Token lifetime defaulted to "+scopeLifetimeFallback+" seconds");
            return scopeLifetimeFallback;
        }
        AuthorizationGrant grant = tokenContext.getGrant();
        Set<String> newScopes = grant.getScopes();
        log.info("Available Scopes: "+newScopes);
        int minLifetime = Integer.MAX_VALUE;
        for(String scope: newScopes) {
            if(static_lifetimes != null) {
                int assciatedLifetime = static_lifetimes.optInt(scope);
                if(assciatedLifetime != 0) {
                    if(assciatedLifetime < minLifetime) minLifetime = assciatedLifetime;
                    continue;
                }
            }
            if(spontaneous_lifetimes != null) {
                int assciatedLifetime = extractLifetime(scope);
                if(assciatedLifetime != 0) {
                    if(assciatedLifetime < minLifetime) minLifetime = assciatedLifetime;
                    continue; //Not necessary but in case we want to change order or add more we leave it
                }
            }
        }
        if(minLifetime == Integer.MAX_VALUE) {
            if(static_lifetimes == null) {
                log.info("Token lifetime defaulted to "+scopeLifetimeFallback+" seconds");
                return scopeLifetimeFallback;
            }
            log.info("Token lifetime defaulted to "+static_lifetimes.optInt("default", scopeLifetimeFallback)+" seconds");
            return static_lifetimes.optInt("default", scopeLifetimeFallback);
        } else {
            log.info("Token lifetime was derived from scopes and set to "+minLifetime+" seconds");
            return minLifetime;
        }
    }

    //Todo: we should have different lifetimes for refresh and access
	@Override
    public int getRefreshTokenLifetimeInSeconds(Object tokenContext){
        log.info("Computing Refresh Token Lifetime");
        return getLifetimeFromScopes((ExternalUpdateTokenContext) tokenContext);
	}

	@Override
    public int getIdTokenLifetimeInSeconds(Object tokenContext){
        log.info("Computing Id Token Lifetime");
        return getLifetimeFromScopes((ExternalUpdateTokenContext) tokenContext);
	}
	
	@Override
    public int getAccessTokenLifetimeInSeconds(Object tokenContext){
        log.info("Computing Access Token Lifetime");
        return getLifetimeFromScopes((ExternalUpdateTokenContext) tokenContext);
	}

}
