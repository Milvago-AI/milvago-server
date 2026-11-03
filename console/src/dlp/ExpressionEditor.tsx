import { detectorName } from './labels';
import { useContext, useId } from 'react';
import { Context, useText } from '../ui';
import type { DlpDetector, DlpExpr } from './types';
import { emptyScope } from './types';

export function ExpressionEditor({ value, change, scope, detectors, field, depth = 0 }: Readonly<{ value: DlpExpr; change: (next: DlpExpr) => void; scope: boolean; detectors: DlpDetector[]; field: string; depth?: number }>) {
  const t = useText(); const {session}=useContext(Context); const valuesId=useId();
   const enterprise=session.edition==='commercial';
  const fields=['channel','provider','tool','device_id','group_id','organization_id',...(enterprise?['model']:[])];
  if ('field' in value && !fields.includes(value.field)) fields.push(value.field);
  const namesByField={channel:t('dlpFieldChannel'),provider:t('dlpFieldProvider'),tool:t('dlpFieldTool'),device_id:t('dlpFieldDevice'),group_id:t('dlpFieldGroup'),model:t('dlpFieldModel'),organization_id:t('dlpFieldOrganization')};
  const suggestions='field' in value ? value.field==='channel'?(['browser',...(enterprise?['native']:[])]):value.field==='provider'?['chatgpt','claude']:value.field==='tool'?['chrome','edge','firefox','brave','chromium']:[]:[];
  const leaf = (): DlpExpr => scope ? emptyScope() : { op: 'contains', field, value: '', ignore_case: true, whole_word: false };
  const grouped = 'children' in value;
  const options = scope ? ['eq', 'in', 'true', 'all', 'any', 'one', 'not'] : ['contains', 'matches', 'upload', 'true', 'all', 'any', 'one', 'not'];
  function choose(op: string) {
    if (op === 'not') change({ op, child: value.op === 'not' ? value.child : value });
    else if (op === 'all' || op === 'any' || op === 'one') change({ op, children: grouped ? value.children : [value, leaf()] });
    else if (op === 'contains') change({ op, field, value: '', ignore_case: true, whole_word: false });
    else if (op === 'matches') change({ op, field, detector: detectors[0]?.id ?? '', minimum: 1 });
    else if (op === 'eq') change({ op, field: 'channel', value: 'browser' });
    else if (op === 'in') change({ op, field: 'channel', values: ['browser'] });
    else change({ op: op as 'true' | 'upload' });
  }
  const names: Record<string, string> = { all: 'AND', any: 'OR', one: 'XOR', not: 'NOT', contains: t('dlpContains'), matches: t('dlpMatches'), upload: t('dlpUpload'), true: t('dlpAlways'), eq: '=', in: 'IN' };
  return <div className={`dlp-expression${grouped ? ' is-group' : ''}`}>
    <div className="dlp-expression-head"><select aria-label={t('dlpOperator')} value={value.op} onChange={event => choose(event.target.value)}>{options.filter(op => depth < 6 || op === value.op || !['all', 'any', 'one', 'not'].includes(op)).map(op => <option key={op} value={op}>{names[op]}</option>)}</select>{value.op === 'one' && <small>{t('dlpExactlyOne')}</small>}</div>
    {grouped && <div className="dlp-expression-children">{value.children.map((child, index) => <div className="dlp-expression-child" key={index}><ExpressionEditor value={child} change={next => change({ ...value, children: value.children.map((item, at) => at === index ? next : item) })} scope={scope} detectors={detectors} field={field} depth={depth + 1} /><button type="button" className="button ghost small" aria-label={t('dlpRemoveCondition')} onClick={() => change(value.children.length === 2 ? value.children[index === 0 ? 1 : 0] : { ...value, children: value.children.filter((_, at) => at !== index) })}>×</button></div>)}<button type="button" className="button secondary small" disabled={value.children.length >= 32} onClick={() => change({ ...value, children: [...value.children, leaf()] })}>{t('dlpAddCondition')}</button></div>}
    {value.op === 'not' && <ExpressionEditor value={value.child} change={child => change({ op: 'not', child })} scope={scope} detectors={detectors} field={field} depth={depth + 1} />}
    {value.op === 'contains' && <><input aria-label={t('dlpExpression')} value={value.value} maxLength={512} onChange={event => change({ ...value, value: event.target.value })} /><div className="dlp-checks"><label><input type="checkbox" checked={value.ignore_case} onChange={event => change({ ...value, ignore_case: event.target.checked })} />{t('dlpIgnoreCase')}</label><label><input type="checkbox" checked={value.whole_word} onChange={event => change({ ...value, whole_word: event.target.checked })} />{t('dlpWholeWord')}</label></div></>}
    {value.op === 'matches' && <><select aria-label={t('dlpDetector')} value={value.detector} onChange={event => change({ ...value, detector: event.target.value })}><option value="">{t('dlpChooseDetector')}</option>{detectors.map(detector => <option key={detector.id} value={detector.id}>{detectorName(t,detector)}</option>)}</select><label>{t('dlpMinimum')}<input type="number" min={1} max={2048} value={value.minimum} onChange={event => change({ ...value, minimum: Number(event.target.value) })} /></label></>}
    {(value.op === 'eq' || value.op === 'in') && <><select aria-label={t('dlpField')} value={value.field} onChange={event => change({ ...value, field: event.target.value })}>{fields.map(item => <option key={item} value={item}>{namesByField[item as keyof typeof namesByField]||item}</option>)}</select><input aria-label={t('dlpScopeValue')} value={value.op === 'eq' ? value.value : value.values.join(', ')} maxLength={1024} list={valuesId} placeholder={suggestions.join(", ")} onChange={event => change(value.op === 'eq' ? { ...value, value: event.target.value } : { ...value, values: event.target.value.split(',').map(v => v.trim()).filter(Boolean) })} /><datalist id={valuesId}>{suggestions.map(item=><option key={item} value={item}/>)}</datalist></>}
  </div>;
}
