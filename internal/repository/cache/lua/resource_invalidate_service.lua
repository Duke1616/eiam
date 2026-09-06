local keys = redis.call('smembers', KEYS[1])
if #keys > 0 then
    redis.call('del', unpack(keys))
end
return redis.call('del', KEYS[1])
