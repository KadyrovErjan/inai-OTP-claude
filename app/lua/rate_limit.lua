-- Fixed-window counter (used for the per-IP verify limit).
-- The window starts with the first request and is never extended by later ones.
--
-- KEYS[1] counter key
-- ARGV[1] limit   ARGV[2] window ms
-- Returns {allowed(1/0), current_count, window_pttl_ms}

local current = redis.call("INCR", KEYS[1])
if current == 1 then
  redis.call("PEXPIRE", KEYS[1], tonumber(ARGV[2]))
end
local ttl = redis.call("PTTL", KEYS[1])
if ttl < 0 then
  -- defensive: a counter must never live forever
  redis.call("PEXPIRE", KEYS[1], tonumber(ARGV[2]))
  ttl = tonumber(ARGV[2])
end
if current > tonumber(ARGV[1]) then
  return {0, current, ttl}
end
return {1, current, ttl}
