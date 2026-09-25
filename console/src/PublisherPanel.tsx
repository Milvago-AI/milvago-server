import { DateValue, Notice, ResourceView, useResource, useText } from './ui';
import type { Translate } from './ui';
type Preview={configured:boolean;auto_catalog:boolean;instance_id:string;telemetry:unknown;last_error:string;last_success?:string;queue?:{state:'empty'|'pending'|'retrying'|'held';attempts:number;next_attempt?:string;created_at?:string}};
function publisherErrorMessage(t: Translate, error: string): string {
  if (error === 'outbox_discarded_configuration_changed') return t('publisherDiscardedConfig');
  if (error === 'outbox_discarded_consent_changed') return t('publisherDiscardedConsent');
  if (error === 'outbox_discarded_expired') return t('publisherDiscardedExpired');
  return error;
}
export function PublisherPanel(){const t=useText(),r=useResource<Preview>('/api/publisher/preview');
 return <ResourceView resource={r}>{d=><div className="publisher-preview"><Notice>{t('publisherPreviewNotice')}</Notice><dl className="dl"><dt>{t('status')}</dt><dd>{d.configured?t('configured'):t('notConfigured')}</dd><dt>{t('publisherLastSuccess')}</dt><dd>{d.last_success?<DateValue value={d.last_success}/>:'—'}</dd></dl>{d.last_error&&<Notice tone="warning">{publisherErrorMessage(t, d.last_error)}</Notice>}{d.queue&&<section><h3>{t('publisherQueue')}</h3><p>{t(({empty:'publisherQueueEmpty',pending:'publisherQueuePending',retrying:'publisherQueueRetrying',held:'publisherQueueHeld'} as const)[d.queue.state])}</p><p>{t('publisherAttempts',[d.queue.attempts])}</p>{d.queue.next_attempt&&<p>{t('publisherNextAttempt')} <DateValue value={d.queue.next_attempt}/></p>}</section>}<pre className="catalog-preview">{JSON.stringify(d.telemetry,null,2)}</pre></div>}</ResourceView>;
}