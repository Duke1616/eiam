local count_key = KEYS[1]
local valid_key = KEYS[2]

-- 1. 减少计数
local count = tonumber(redis.call("GET", count_key) or "0")
local new_count = 0
if count > 0 then
    new_count = redis.call("DECR", count_key)
end

-- 2. 恢复标识位
redis.call("SET", valid_key, "1")

return tostring(new_count)
