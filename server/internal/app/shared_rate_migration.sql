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
  -- Only admission of a new key holds this cardinality lock.
  SELECT keys INTO cardinality FROM public.rate_windows WHERE family=p_family AND window_start=minute FOR UPDATE;
  SELECT hits INTO spent FROM public.rate_counters
   WHERE family=p_family AND window_start=minute AND key_hash=p_key FOR UPDATE;
  IF NOT FOUND THEN
   IF cardinality>=16384 AND p_family<>3 THEN
    -- Full: admitted, not counted. Refusing let 16384 keys -- a fleet of a few
    -- thousand devices, or as many source addresses -- lock every new caller out for
    -- the minute (audit of 2026-09-24). The totals, counted from the first request
    -- of the minute, still bound the public operations.
    granted:=least(p_amount,p_budget);
   ELSE
    granted:=least(p_amount,p_budget);
    INSERT INTO public.rate_counters(family,window_start,key_hash,hits) VALUES(p_family,minute,p_key,granted);
    UPDATE public.rate_windows SET keys=keys+1 WHERE family=p_family AND window_start=minute;
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
