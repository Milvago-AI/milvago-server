import { useContext } from 'react';
import { Badge, can, Context, useText } from '../ui';
import type { DlpDecision, DlpTrace } from './types';
import './dlp.css';
import {dlpAction,dlpTruth,dlpOutcome} from './labels';

export function DlpTraceView({trace, compact=false,device}:Readonly<{trace?:DlpTrace;compact?:boolean;device?:string}>) {
  const t=useText(); const {session}=useContext(Context);
  if(!trace) return compact?null:<p className="muted">{t('dlpNoAttribution')}</p>;
  const delivery=({not_sent:t('dlpNotSent'),prepared:t('dlpPrepared'),observed:t('dlpObserved'),unknown:t('dlpUnknown'),cancelled:t('dlpCancelled')} as Record<string,string>)[trace.delivery]??t('dlpUnknown');
  if(compact) return <span className="dlp-bubble-evidence"><IconShield />{trace.decisions.map(d=><span key={d.rule_id} title={`${d.rule_id} · ${t('dlpRuleRevision',[d.rule_revision])}`}>{d.rule_name}</span>)} · {delivery}</span>;
  return <section className="dlp-event-decisions"><h3>{t('dlpDecisionTitle')}</h3><p>{t('dlpDelivery')} : {delivery}</p><DlpDecisionList decisions={trace.decisions} device={device} manage={can(session,'policy.manage')} /><small className="mono">{trace.fingerprint}</small></section>;
}
function IconShield(){return <span aria-hidden="true">◈</span>;}

export function DlpDecisionList({ decisions, manage = false, device }: Readonly<{ decisions: DlpDecision[]; manage?: boolean;device?:string }>) {
  const t = useText();
  const outcome = (value:string)=>dlpOutcome(t,value);
  return <div className="dlp-decision-list">{decisions.map(decision => <article className="dlp-decision" key={`${decision.rule_id}:${decision.rule_revision}`}><div><strong>{decision.rule_name}</strong><Badge tone={decision.outcome.includes('blocked') ? 'danger' : decision.mode === 'simulation' ? 'warning' : 'neutral'}>{outcome(decision.outcome)}</Badge></div><code className="cell-detail" aria-label={t('dlpRuleIdentifier')}>{decision.rule_id}</code><p>{t('dlpRuleRevision', [decision.rule_revision])} · {t(decision.mode==='simulation'?'dlpSimulation':'dlpActive')} · {dlpAction(t,decision.consequence)} · {t('dlpOccurrenceCount', [decision.occurrences])}</p><small>{t('dlpConditionState')} : {dlpTruth(t,decision.condition)} · {t('dlpScopeState')} : {dlpTruth(t,decision.scope)}</small>{manage && <a className="button ghost small" href={`#dlp?${device?`device=${encodeURIComponent(device)}&`:''}rule=${encodeURIComponent(decision.rule_id)}`}>{t('dlpOpenRule')}</a>}</article>)}</div>;
}

