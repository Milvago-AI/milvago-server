import {useEffect,useState} from 'react';
import {useText} from '../ui';
import {createDlpEngine} from './engine';
import {detectorName,dlpAction} from './labels';
import type {DlpEffect,DlpPolicy,DlpRule} from './types';

type Target={value:string;ignore_case:boolean;whole_word:boolean};
type Options={masks:string[];replacements:Target[];warn:boolean;review:boolean;valid:boolean;error?:string};
export function ConsequenceEditor({rule,policy,engine,change}:Readonly<{rule:DlpRule;policy:DlpPolicy;engine:ReturnType<typeof createDlpEngine>;change:(rule:DlpRule)=>void}>){
 const t=useText();const [options,setOptions]=useState<Options>();const [failed,setFailed]=useState(false);
 useEffect(()=>{let active=true;setOptions(undefined);setFailed(false);engine.call({op:'consequences',policy,rule}).then(value=>{if(active)setOptions(value.options as Options);}).catch(()=>{if(active)setFailed(true);});return()=>{active=false;};},[engine,policy,rule]);
 const effect=rule.consequence;
 const permitted=(action:string)=>action==='observe'||action==='block'||!!options&&(action==='warn'?options.warn:action==='mask'?options.masks.length>0:options.replacements.length>0);
 function select(action:string){
  let consequence:DlpEffect;
  if(action==='mask')consequence={action,detector:options?.masks[0]||'',label:'REDACTED'};
  else if(action==='replace')consequence={action,...options!.replacements[0],replacement:''};
  else consequence={action:action as 'observe'|'block'|'warn'};
  change({...rule,consequence,review:false,message:action==='warn'?(rule.message||t('dlpWarningDefault')):action==='block'?rule.message:''});
 }
 const errorKey=({audit_has_no_user_message:'dlpAuditMessageInvalid',confirmation_requires_browser:'dlpConfirmationBrowser',confirmation_message_required:'dlpConfirmationMessage',mask_requires_positive_match:'dlpMaskTargetHint',mask_label_matches_detector:'dlpMaskLabelInvalid',replace_requires_positive_literal:'dlpReplaceTargetHint',review_requires_browser:'dlpConfirmationBrowser'} as const)[options?.error as 'audit_has_no_user_message'];
 const target=effect.action==='replace'?options?.replacements.findIndex(item=>item.value===effect.value&&item.ignore_case===effect.ignore_case&&item.whole_word===effect.whole_word):-1;
 return <><select aria-label={t('dlpConsequence')} value={effect.action} onChange={event=>select(event.target.value)}>{['observe','warn','block','mask','replace'].map(action=><option key={action} value={action} disabled={!permitted(action)}>{dlpAction(t,action)}</option>)}</select>
 <p className="field-help">{effect.action==='observe'?t('dlpAuditHint'):effect.action==='warn'?t('dlpConfirmHint'):effect.action==='mask'?t('dlpMaskTargetHint'):effect.action==='replace'?t('dlpReplaceTargetHint'):t('dlpBlockHint')}</p>
 {!options&&<p role="status" className="field-help">{t(failed?'dlpConsequenceUnavailable':'dlpChecking')}</p>}
 {options?.error&&<p role="alert" className="dlp-diagnostic">{t(errorKey||'dlpConsequenceUnavailable')}</p>}
 {effect.action==='observe'&&rule.message&&<button type="button" onClick={()=>change({...rule,message:''})}>{t('dlpClearAuditMessage')}</button>}
 {effect.action==='mask'&&<><select aria-label={t('dlpDetector')} value={effect.detector} onChange={event=>change({...rule,consequence:{...effect,detector:event.target.value}})}>{!options?.masks.includes(effect.detector)&&<option value={effect.detector}>{policy.detectors.find(d=>d.id===effect.detector)?.name||t('dlpChooseDetector')}</option>}{policy.detectors.filter(d=>options?.masks.includes(d.id)).map(d=><option key={d.id} value={d.id}>{detectorName(t,d)}</option>)}</select><label>{t('dlpMaskLabel')}<input maxLength={60} value={effect.label} onChange={event=>change({...rule,consequence:{...effect,label:event.target.value}})}/></label></>}
 {effect.action==='replace'&&<><label>{t('dlpFind')}<select value={target??-1} onChange={event=>{const selected=options?.replacements[Number(event.target.value)];if(selected)change({...rule,consequence:{...effect,...selected}});}}>{(target===undefined||target<0)&&<option value={-1}>{effect.value||t('dlpChooseReplacement')}</option>}{options?.replacements.map((item,index)=><option key={index} value={index}>{item.value} · {t(item.ignore_case?'dlpIgnoreCase':'dlpCaseSensitive')}{item.whole_word?' · '+t('dlpWholeWord'):''}</option>)}</select></label><label>{t('dlpReplacement')}<input maxLength={1024} value={effect.replacement} onChange={event=>change({...rule,consequence:{...effect,replacement:event.target.value}})}/></label></>}
 {(effect.action==='replace'||effect.action==='mask')&&<label className="dlp-checkbox"><input type="checkbox" disabled={!options?.review&&!rule.review} checked={rule.review} onChange={event=>change({...rule,review:event.target.checked})}/>{t('dlpReview')}</label>}
 {(effect.action==='block'||effect.action==='warn'||rule.review)&&<label>{t('dlpUserMessage')}<textarea rows={3} maxLength={1000} required={effect.action==='warn'} value={rule.message} onChange={event=>change({...rule,message:event.target.value})}/></label>}
 {options&&!options.warn&&<p className="field-help">{t('dlpConfirmationBrowser')}</p>}
 </>;
}
