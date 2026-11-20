-- Atomically finalize one verification attempt.
--
-- The constant-time HMAC comparison is done in Python (hmac.compare_digest);
-- this script only receives its RESULT and re-checks, atomically, that the
-- challenge the comparison was made against is still the current one.
--
-- KEYS[1] block   KEYS[2] active   KEYS[3] fail counter   KEYS[4] spent
--
-- ARGV[1] mode: "match"   - code matched challenge ARGV[2]
--               "nomatch" - code did not match challenge ARGV[2]
--               "spent"   - code matched an already replaced/used challenge ARGV[2]
--               "none"    - there was no current challenge
-- ARGV[2] challenge id seen by Python ("" for "none")
-- ARGV[3] max wrong attempts   ARGV[4] block ms   ARGV[5] fail-counter window ms
-- ARGV[6] spent ttl ms
--
-- Returns
--   {"blocked", pttl_ms}                    phone is blocked (423)
--   {"verified"}                            success, challenge consumed (200)
--   {"invalid", attempts_left}              wrong code (401)
--   {"blocked_now", block_ms}               5th wrong code, block started (423)
--   {"gone", reason}                        expired / used / replaced (410)

local block_ttl = redis.call("PTTL", KEYS[1])
if block_ttl > 0 then
  return {"blocked", block_ttl}
end

local mode = ARGV[1]
local cid = ARGV[2]

local function gone_reason(c)
  if c ~= "" then
    local r = redis.call("HGET", KEYS[4], "r:" .. c)
    if r then return r end
  end
  return "expired"
end

if mode == "none" then
  return {"gone", "expired"}
end

if mode == "spent" then
  return {"gone", gone_reason(cid)}
end

local current = redis.call("HGET", KEYS[2], "cid")
if not current then
  -- consumed by a concurrent request or expired after Python read it
  return {"gone", gone_reason(cid)}
end
if current ~= cid then
  -- replaced by a newer /otp/send between the read and this script
  return {"gone", "replaced"}
end

if mode == "match" then
  local digest = redis.call("HGET", KEYS[2], "digest")
  redis.call("DEL", KEYS[2])
  redis.call("DEL", KEYS[3])
  redis.call("HSET", KEYS[4], cid, digest, "r:" .. cid, "used")
  redis.call("PEXPIRE", KEYS[4], tonumber(ARGV[6]))
  return {"verified"}
end

-- wrong code against the current challenge
local fails = redis.call("INCR", KEYS[3])
if fails == 1 then
  redis.call("PEXPIRE", KEYS[3], tonumber(ARGV[5]))
end
local max_attempts = tonumber(ARGV[3])
if fails >= max_attempts then
  redis.call("SET", KEYS[1], "1", "PX", tonumber(ARGV[4]))
  -- reset so the next wrong code after the block expires does not re-block instantly,
  -- and burn the attacked challenge so brute force cannot resume after the block
  redis.call("DEL", KEYS[3])
  redis.call("DEL", KEYS[2])
  return {"blocked_now", tonumber(ARGV[4])}
end
return {"invalid", max_attempts - fails}
