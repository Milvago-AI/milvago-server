import { useEffect, useState } from 'react';
import { onSecondFactorChallenge, verifySecondFactor } from './secondFactor';
import type { SecondFactorChallenge } from './secondFactor';
import { Dialog, useText } from './ui';

/** Confirmation shared by every mutation requiring a recent second factor. */
export function SecondFactorConfirmation() {
  const t = useText();
  const [challenge, setChallenge] = useState<SecondFactorChallenge>();
  useEffect(() => onSecondFactorChallenge(setChallenge), []);
  if (!challenge) return null;
  return <Dialog title={t('verifySecondFactorBeforeDownload')} close={() => setChallenge(undefined)}>
    <div className="dialog-body"><p>{t('secondFactorConfirmationNotice')}</p></div>
    <div className="dialog-actions">
      <button type="button" className="button secondary" onClick={() => setChallenge(undefined)}>{t('cancel')}</button>
      <button type="button" className="button primary" onClick={() => {
        setChallenge(undefined);
        verifySecondFactor(challenge.path, challenge.method, challenge.body, challenge.error, challenge.language, challenge.scope);
      }}>{t('continueToSecondFactor')}</button>
    </div>
  </Dialog>;
}
