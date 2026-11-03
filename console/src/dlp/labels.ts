import type {Translate} from '../ui';
export function dlpAction(t:Translate,value:string){return ({observe:t('dlpObserve'),warn:t('dlpWarn'),block:t('dlpBlock'),mask:t('dlpMask'),replace:t('dlpReplace'),transform:t('dlpTransformed'),review:t('dlpReviewPending')} as Record<string,string>)[value]||t('dlpUnknown');}
export function dlpTruth(t:Translate,value:string){return ({true:t('dlpYes'),false:t('dlpNo'),unknown:t('dlpUnknown')} as Record<string,string>)[value]||t('dlpUnknown');}
export function dlpOutcome(t:Translate,value:string){return ({simulated:t('dlpSimulated'),blocked:t('dlpBlocked'),unavailable:t('dlpUnavailable'),prepared:t('dlpPrepared'),observed:t('dlpObserved'),overridden:t('dlpOverridden'),final_blocked:t('dlpFinalBlocked'),cancelled:t('dlpCancelled'),observed_after_send:t('dlpObservedAfterSend'),matched:t('dlpMatched')} as Record<string,string>)[value]||t('dlpUnknown');}
export function dlpStatus(t:Translate,value:string){return ({disabled:t('dlpDisabled'),applied:t('applied'),pending:t('pending'),needs_update:t('needsUpdate'),unavailable:t('dlpUnavailable')} as Record<string,string>)[value]||t('dlpUnknown');}
export function dlpDetector(t:Translate,value:string){return ({literal:t('dlpLiteral'),regex:t('dlpRegularExpression'),dictionary:t('dlpDictionary'),builtin:t('dlpBuiltIn'),keyword:t('dlpExpression'),keyword_tier:t('dlpDictionary'),dictionary_context:t('dlpDictionaryContext')} as Record<string,string>)[value]||t('dlpUnknown');}

export function builtinName(t:Translate,category:string){return ({email:t('dlpBuiltinEmail'),phone:t('dlpBuiltinPhone'),iban:t('dlpBuiltinIban'),card:t('dlpBuiltinCard'),social_id:t('dlpBuiltinNir'),fr_nir:t('dlpBuiltinNir'),ssn_us:t('dlpBuiltinSsn'),us_ssn:t('dlpBuiltinSsn'),ca_sin:t('dlpBuiltinSin'),ch_avs:t('dlpBuiltinAvs'),ip:t('dlpBuiltinIp'),source_code:t('dlpBuiltinSource'),medical:t('dlpBuiltinMedical')} as Record<string,string>)[category]||category;}

export function detectorName(t:Translate,detector:import('./types').DlpDetector):string{
 return detector.definition.kind==='builtin'?builtinName(t,detector.definition.category):detector.name;
}

export function ruleName(t:Translate,rule:import('./types').DlpRule,policy:import('./types').DlpPolicy):string{
 if(!rule.id.startsWith('preset-')||rule.condition.op!=='matches')return rule.name;
 const detector=policy.detectors.find(d=>d.id===(rule.condition.op==='matches'?rule.condition.detector:''));
 if(!detector||detector.definition.kind!=='builtin'||!['mask','block'].includes(rule.consequence.action))return rule.name;
 const original=(rule.consequence.action==='mask'?'Mask: ':'Block: ')+detector.name;
 return rule.name===original?`${dlpAction(t,rule.consequence.action)} · ${builtinName(t,detector.definition.category)}`:rule.name;
}
