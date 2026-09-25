import { ApiError } from './api';
import { useContext, useState } from 'react';
import { can, Context, DateValue, ErrorNotice, useMutation, useText } from './ui';
export function IdentityReveal({ subject, expiresAt }: Readonly<{ subject?: string; expiresAt?: string }>) {
 const t=useText(),{session}=useContext(Context),m=useMutation(),[reason,setReason]=useState(''),[localError,setLocalError]=useState<unknown>();
 if(!subject||subject==='unknown'||!can(session,'identity.reveal'))return null;
 async function submit(){if(reason.trim().length<8){return;}setLocalError(undefined);try{const result=await m.run<{expires_at:string}>(`/api/subjects/${encodeURIComponent(subject! )}/reveal`,'POST',{reason:reason.trim()});if(!result?.expires_at){throw new ApiError(502,'invalid_response',t('invalidServerResponse'));}setReason('');window.dispatchEvent(new Event('milvago:privacy-changed'))}catch(e){setLocalError(e)}}
 return <section>{expiresAt?<p>{t('identityVisibleUntil')} <DateValue value={expiresAt}/></p>:<form onSubmit={e=>{e.preventDefault();void submit()}} className="form-grid"><label>{t('privacyChangeReason')}<textarea required minLength={8} maxLength={1000} value={reason} onChange={e=>setReason(e.target.value)}/></label><small className="field-help">{t('privacyChangeReasonHelp')}</small><ErrorNotice error={localError||m.error}/><button type="submit" className="button secondary" disabled={m.pending||reason.trim().length<8}>{t('revealIdentity')}</button></form>}</section>;
}
