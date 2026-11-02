local keys = redis.call('smembers', KEYS[1])
if #keys > 0 then
    for i = 1, #keys, 500 do
        local batch = {}
        for j = i, math.min(i + 499, #keys) do
            table.insert(batch, keys[j])
        end
        redis.call('del', unpack(batch))
    end
end
return redis.call('del', KEYS[1])
