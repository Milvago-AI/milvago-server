export function flows() {
 const execution = (authenticator,priority,authenticatorConfig) => ({authenticator,priority,requirement:'REQUIRED',authenticatorFlow:false,...(authenticatorConfig?{authenticatorConfig}:{})});
 const sub = (flowAlias,priority,requirement) => ({flowAlias,priority,requirement,authenticatorFlow:true});
 const flow = (alias,topLevel,authenticationExecutions) => ({alias,description:'Milvago OIDC authentication',providerId:'basic-flow',topLevel,builtIn:false,authenticationExecutions});
 const definition = {
  browserFlow:'milvago-browser',
  firstBrokerLoginFlow:'first broker login',
  authenticationFlows:[
   flow('milvago-browser',true,[{...execution('auth-cookie',10),requirement:'ALTERNATIVE'},sub('milvago-interactive',20,'ALTERNATIVE')]),
   flow('milvago-interactive',false,[sub('milvago-level-one',10,'CONDITIONAL'),sub('milvago-level-two',20,'CONDITIONAL')]),
   flow('milvago-level-one',false,[execution('conditional-level-of-authentication',10,'milvago-loa-one'),execution('auth-username-password-form',20)]),
   flow('milvago-level-two',false,[execution('conditional-level-of-authentication',10,'milvago-loa-two'),execution('auth-otp-form',20)]),
  ],
  authenticatorConfig:[
   {alias:'milvago-loa-one',config:{'loa-condition-level':'1','loa-max-age':'36000'}},
   {alias:'milvago-loa-two',config:{'loa-condition-level':'2','loa-max-age':'0'}},
  ],
  attributes:{'acr.loa.map':'{"1":1,"2":2}'},
 };
 return JSON.parse(JSON.stringify(definition).replaceAll('milvago-','milvago-v1-'));
}

export const safeBrokerLoginFlow='first broker login';
export const isLegacyBrokerLogin=alias=>['milvago-first-broker-login','milvago-v1-first-broker-login'].includes(alias);

// Disabled components keep their configuration and credentials for operator repair.
// An insecure configuration is never silently upgraded or switched to a guessed URL.
export function disabledInsecureDirectory(component){
 if(component.providerId!=='ldap'||component.config?.enabled?.[0]==='false')return null;
 const config=component.config||{};
 const urls=config.connectionUrl?.[0]?.trim().split(/\s+/)||[];
 const encrypted=urls.length>0&&urls.every(value=>{
  try{const url=new URL(value);return url.protocol==='ldaps:'||(url.protocol==='ldap:'&&config.startTls?.[0]==='true');}catch{return false;}
 });
 if(encrypted&&config.useTruststoreSpi?.[0]==='always')return null;
 return {...component,config:{...config,enabled:['false']}};
}

export function secureIdentityTemplate(template){
 const secured=structuredClone(template);
 if(!secured.firstBrokerLoginFlow||isLegacyBrokerLogin(secured.firstBrokerLoginFlow))secured.firstBrokerLoginFlow=safeBrokerLoginFlow;
 for(const provider of secured.identityProviders||[]){
  if(isLegacyBrokerLogin(provider.firstBrokerLoginFlowAlias))provider.firstBrokerLoginFlowAlias=safeBrokerLoginFlow;
 }
 for(const components of Object.values(secured.components||{})){
  for(let i=0;i<components.length;i++)components[i]=disabledInsecureDirectory(components[i])||components[i];
 }
 return secured;
}
