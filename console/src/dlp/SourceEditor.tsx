import {useRef} from 'react';
import type {RefObject} from 'react';

const tokens=/("(?:[^"\\]|\\.)*"|\b(?:WHEN|SCOPE|THEN|AND|OR|XOR|NOT|TRUE|CONTAINS|MATCHES|ATLEAST|IN|UPLOAD|OBSERVE|WARN|BLOCK|MASK|AS|REPLACE|WITH|IGNORECASE|WORD|REVIEW|MESSAGE|detector)\b)/gi;
export function SourceEditor({inputRef,value,change,label,diagnostic,caretChanged}:Readonly<{inputRef:RefObject<HTMLTextAreaElement|null>;value:string;change:(value:string)=>void;label:string;diagnostic:string;caretChanged:()=>void}>) {
  const code=useRef<HTMLPreElement>(null);const gutter=useRef<HTMLPreElement>(null);
  const parts=value.split(tokens);
  const errorLine=Number(/^(\d+):\d+:/.exec(diagnostic)?.[1]||0);
  return <div className="dlp-source-editor"><pre className="dlp-source-gutter" ref={gutter} aria-hidden="true">{value.split('\n').map((_,index)=><span className={index+1===errorLine?'error-line':''} key={index}>{index+1}{'\n'}</span>)}</pre><div className="dlp-source-content"><pre ref={code} className="dlp-source-highlight" aria-hidden="true">{parts.length>4096?value:parts.map((part,index)=><span key={index} className={index%2?(part.startsWith('"')?'dlp-token-string':'dlp-token-keyword'):undefined}>{part}</span>)}{'\n'}</pre><textarea ref={inputRef} aria-label={label} spellCheck={false} rows={18} maxLength={16384} value={value} onChange={event=>change(event.target.value)} onSelect={caretChanged} onKeyUp={caretChanged} onScroll={event=>{if(code.current){code.current.scrollTop=event.currentTarget.scrollTop;code.current.scrollLeft=event.currentTarget.scrollLeft;}if(gutter.current)gutter.current.scrollTop=event.currentTarget.scrollTop;}} aria-invalid={!!diagnostic} /></div></div>;
}
