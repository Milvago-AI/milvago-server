-- Global technical counters contain no tenant contents or plaintext credentials.
CREATE TABLE IF NOT EXISTS rate_windows (
 family smallint NOT NULL CHECK (family IN (1,2,3)),
 window_start timestamptz NOT NULL,
 keys integer NOT NULL DEFAULT 0 CHECK (keys BETWEEN 0 AND 16384),
 PRIMARY KEY(family,window_start)
);
CREATE TABLE IF NOT EXISTS rate_counters (
 family smallint NOT NULL,
 window_start timestamptz NOT NULL,
 key_hash bytea NOT NULL CHECK (octet_length(key_hash)=32),
 hits integer NOT NULL CHECK (hits BETWEEN 1 AND 60000),
 PRIMARY KEY(family,window_start,key_hash),
 FOREIGN KEY(family,window_start) REFERENCES rate_windows ON DELETE CASCADE
);
-- Family 3 holds the per-operation totals of the public routes (2026-09-24). They are
-- a fixed handful of keys, so they sit outside the cardinality cap: a window filled
-- with peer keys must never leave a total uncounted. Converged on every boot.
ALTER TABLE rate_windows DROP CONSTRAINT IF EXISTS rate_windows_family_check;
ALTER TABLE rate_windows ADD CONSTRAINT rate_windows_family_check CHECK (family IN (1,2,3));
-- Reserving at most 32 units amortizes the public, high-frequency counters.
-- PostgreSQL charges every reserved unit before any replica can spend it.
CREATE OR REPLACE FUNCTION reserve_rate_budget(p_family smallint,p_key bytea,p_budget integer,p_amount integer)
RETURNS TABLE(granted integer,valid_for_ms bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $rate$
DECLARE minute timestamptz := date_trunc('minute',clock_timestamp()); cardinality integer; spent integer;
BEGIN
 IF p_family IS NULL OR p_family NOT IN (1,2,3) OR p_key IS NULL OR octet_length(p_key)<>32
    OR p_budget IS NULL OR p_budget<1 OR p_budget>60000
    OR p_amount IS NULL OR p_amount<1 OR p_amount>32 THEN
  RAISE EXCEPTION 'invalid rate budget';
 END IF;
 SELECT hits INTO spent FROM public.rate_counters
  WHERE family=p_family AND window_start=minute AND key_hash=p_key FOR UPDATE;
 IF NOT FOUND THEN
  INSERT INTO public.rate_windows(family,window_start) VALUES(p_family,minute) ON CONFLICT DO NOTHING;
  -- Protect the parent from cleanup without blocking other counters' FK checks.
  SELECT keys INTO cardinality FROM public.rate_windows WHERE family=p_family AND window_start=minute FOR KEY SHARE;
  IF NOT FOUND THEN
   RAISE EXCEPTION 'rate window unavailable';
  END IF;
  granted:=least(p_amount,p_budget);
  IF cardinality>=16384 AND p_family<>3 THEN
   -- A committed full window cannot gain another counted key. Recheck a key
   -- committed between our first lookup and the full-window observation.
   SELECT hits INTO spent FROM public.rate_counters
    WHERE family=p_family AND window_start=minute AND key_hash=p_key FOR UPDATE;
  ELSE
   INSERT INTO public.rate_counters(family,window_start,key_hash,hits) VALUES(p_family,minute,p_key,granted)
    ON CONFLICT DO NOTHING RETURNING hits INTO spent;
   IF FOUND THEN
    -- Only the successful new row claims a slot. The non-key update takes
    -- NO KEY UPDATE, compatible with concurrent child FK KEY SHARE locks.
    UPDATE public.rate_windows SET keys=keys+1
     WHERE family=p_family AND window_start=minute AND (keys<16384 OR p_family=3)
     RETURNING keys INTO cardinality;
    IF NOT FOUND THEN
     -- Another new key took the last slot. Preserve admitted/not-counted
     -- saturation behavior; this transaction owns this uncommitted row only.
     DELETE FROM public.rate_counters WHERE family=p_family AND window_start=minute AND key_hash=p_key;
    END IF;
    spent:=NULL;
   ELSE
    -- A same-key contender charged the first request; charge this one too.
    SELECT hits INTO spent FROM public.rate_counters
     WHERE family=p_family AND window_start=minute AND key_hash=p_key FOR UPDATE;
    IF NOT FOUND THEN
     RAISE EXCEPTION 'rate counter unavailable';
    END IF;
   END IF;
  END IF;
 END IF;
 IF spent IS NOT NULL THEN
  granted:=greatest(0,least(p_amount,p_budget-spent));
  IF granted>0 THEN
   UPDATE public.rate_counters SET hits=hits+granted
    WHERE family=p_family AND window_start=minute AND key_hash=p_key;
  END IF;
 END IF;
 valid_for_ms:=greatest(0,floor(extract(epoch FROM (minute+interval '1 minute'-clock_timestamp()))*1000))::bigint;
 RETURN NEXT;
END $rate$;
CREATE OR REPLACE FUNCTION consume_rate_budget(p_family smallint,p_key bytea,p_budget integer)
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $rate$
 SELECT granted=1 FROM public.reserve_rate_budget(p_family,p_key,p_budget,1);
$rate$;
CREATE OR REPLACE FUNCTION cleanup_rate_budgets() RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $rate$
 DELETE FROM public.rate_windows WHERE window_start < date_trunc('minute',clock_timestamp())-interval '2 minutes';
$rate$;
REVOKE ALL ON rate_windows,rate_counters FROM PUBLIC;
REVOKE ALL ON FUNCTION reserve_rate_budget(smallint,bytea,integer,integer),consume_rate_budget(smallint,bytea,integer),cleanup_rate_budgets() FROM PUBLIC;
