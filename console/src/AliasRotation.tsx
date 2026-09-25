import { ApiError } from './api';
import { useState } from 'react';
import { Card, ErrorNotice, Notice, useMutation, useText } from './ui';
export function AliasRotation({ done }: Readonly<{ done: () => void }>) {
 const t=useText(),m=useMutation(),[reason,setReason]=useState(''),[subjects,setSubjects]=useState<number>(),[localError,setLocalError]=useState<unknown>();
 async function submit(){if(reason.trim().length<8){return;}setLocalError(undefined);try{const result=await m.run<{subjects:number}>('/api/privacy/alias-key/rotate','POST',{reason:reason.trim()});if(!result||!Number.isInteger(result.subjects)){throw new ApiError(502,'invalid_response',t('invalidServerResponse'));}setSubjects(result.subjects);setReason('');window.dispatchEvent(new Event('milvago:privacy-changed'));done()}catch(e){setLocalError(e)}}
 return <Card title={t('rotateAliases')}><p>{t('aliasesLinkEventsFromTheSamePerson')}</p><form onSubmit={e=>{e.preventDefault();void submit()}} className="form-grid"><Notice tone="warning">{t('rotateAliasesWarning')}</Notice>{subjects!==undefined&&<Notice>{t('aliasesRotated',[subjects])}</Notice>}<label>{t('privacyChangeReason')}<textarea required minLength={8} maxLength={1000} value={reason} onChange={e=>setReason(e.target.value)}/></label><small className="field-help">{t('privacyChangeReasonHelp')}</small><ErrorNotice error={localError||m.error}/><button type="submit" className="button danger" disabled={m.pending||reason.trim().length<8}>{t('confirmRotation')}</button></form></Card>;
}
