-- Atomically issue a new OTP challenge for one phone.
--
-- KEYS[1] block     phone block flag          (TTL = block duration)
-- KEYS[2] send      send-window hash {count}  (TTL = 600 s from the first send in the window)
-- KEYS[3] cooldown  cooldown flag             (TTL = 30 / 60 / 120 s)
-- KEYS[4] active    current challenge hash {cid, digest} (TTL = OTP lifetime)
-- KEYS[5] spent     superseded / used challenges {cid -> digest, "r:"..cid -> reason}
--
-- ARGV[1] challenge id      ARGV[2] HMAC digest (never the OTP itself)
-- ARGV[3] otp ttl ms        ARGV[4] send window ms     ARGV[5] max sends per window
-- ARGV[6] spent ttl ms      ARGV[7..] cooldown ms for the 1st, 2nd, 3rd ... send
--
-- Returns {status, a, b, c}
--   {"blocked",  block_pttl_ms}
--   {"cooldown", cooldown_pttl_ms, sends_used}
--   {"limit",    retry_ms,         sends_used}
--   {"ok",       sends_used, cooldown_ms, replaced(0/1)}

local block_ttl = redis.call("PTTL", KEYS[1])
if block_ttl > 0 then
  return {"blocked", block_ttl}
end

local count = tonumber(redis.call("HGET", KEYS[2], "count") or "0")
local max_send = tonumber(ARGV[5])

local cooldown_ttl = redis.call("PTTL", KEYS[3])
if count >= max_send then
  local window_ttl = redis.call("PTTL", KEYS[2])
  if cooldown_ttl > window_ttl then window_ttl = cooldown_ttl end
  return {"limit", window_ttl, count}
end
if cooldown_ttl > 0 then
  return {"cooldown", cooldown_ttl, count}
end

-- move the still-valid previous challenge to "spent" so its code is reported as
-- replaced (410) instead of being counted as a wrong guess
local replaced = 0
local old = redis.call("HMGET", KEYS[4], "cid", "digest")
if old[1] and old[2] then
  redis.call("HSET", KEYS[5], old[1], old[2], "r:" .. old[1], "replaced")
  redis.call("PEXPIRE", KEYS[5], tonumber(ARGV[6]))
  replaced = 1
end

redis.call("DEL", KEYS[4])
redis.call("HSET", KEYS[4], "cid", ARGV[1], "digest", ARGV[2])
redis.call("PEXPIRE", KEYS[4], tonumber(ARGV[3]))

-- the 600 s window starts with the first successful send; refused sends never touch it
local new_count = redis.call("HINCRBY", KEYS[2], "count", 1)
if new_count == 1 then
  redis.call("PEXPIRE", KEYS[2], tonumber(ARGV[4]))
end

local idx = 6 + new_count
if idx > #ARGV then idx = #ARGV end
local cooldown_ms = tonumber(ARGV[idx])
if cooldown_ms > 0 then
  redis.call("SET", KEYS[3], "1", "PX", cooldown_ms)
end

return {"ok", new_count, cooldown_ms, replaced}
