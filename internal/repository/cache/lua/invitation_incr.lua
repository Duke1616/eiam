local count_key = KEYS[1]
local valid_key = KEYS[2]
local max_uses = tonumber(ARGV[1])

-- 1. 检查有效性
if redis.call("EXISTS", valid_key) == 0 then
    return "NOT_FOUND"
end

-- 2. 检查上限
local count = tonumber(redis.call("GET", count_key) or "0")
if max_uses > 0 and count >= max_uses then
    return "FULL"
end

-- 3. 增加计数
local new_count = redis.call("INCR", count_key)

-- 4. 自动闭环
if max_uses > 0 and new_count >= max_uses then
    redis.call("DEL", valid_key)
end

-- 返回新的计数字符串，以便 Go 解析
return tostring(new_count)
