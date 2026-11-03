package app

// The web inventory stays exact across the retained history. Its partial covering
// index avoids reading unrelated events without changing tenant or privacy gates.
const candidateDomainsQuery = `SELECT jsonb_build_object(
 'discovery_enabled',$4::boolean,
 'items',coalesce((SELECT jsonb_agg(c) FROM (SELECT domain,count,first_seen,last_seen,status FROM candidate_domains WHERE domain<>ALL($3) ORDER BY last_seen DESC LIMIT 500) c),'[]'),
 'platforms',coalesce((SELECT jsonb_agg(p) FROM (
   SELECT provider,count(*) visits,count(*) FILTER(WHERE action='blocked') blocked,count(DISTINCT device_id) devices,count(DISTINCT user_key) FILTER(WHERE user_key<>'') accounts,max(occurred_at) last_seen
   FROM shadow_events WHERE detector='presence' AND provider<>ALL($2) AND provider<>ALL($3) GROUP BY provider HAVING count(DISTINCT device_id)>=$1 ORDER BY max(occurred_at) DESC LIMIT 256) p),'[]'))`
