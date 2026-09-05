package redisx

import (
	"context"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

type demoPayload struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func TestJSONSerializer(t *testing.T) {
	ser := JSONSerializer[demoPayload]{}

	p := demoPayload{ID: 100, Name: "tester"}
	str, err := ser.Marshal(p)
	assert.NoError(t, err)
	assert.Contains(t, str, `"id":100`)

	var got demoPayload
	err = ser.Unmarshal(str, &got)
	assert.NoError(t, err)
	assert.Equal(t, p, got)

	// 测试损坏 JSON
	var bad demoPayload
	err = ser.Unmarshal("{invalid-json", &bad)
	assert.Error(t, err)
}

func TestStreamQueue_ParseMessages(t *testing.T) {
	q := &streamQueue[demoPayload]{
		serializer: JSONSerializer[demoPayload]{},
		payloadKey: DefaultPayloadKey,
	}

	messages := []redis.XMessage{
		{
			ID: "1-0",
			Values: map[string]interface{}{
				"payload": `{"id":1,"name":"alice"}`,
			},
		},
		{
			ID: "2-0",
			Values: map[string]interface{}{
				"other_field": "123",
			},
		},
		{
			ID: "3-0",
			Values: map[string]interface{}{
				"payload": 12345, // 非字符串
			},
		},
		{
			ID: "4-0",
			Values: map[string]interface{}{
				"payload": "{invalid-json",
			},
		},
	}

	parsed := q.parseMessages(messages)
	assert.Equal(t, 4, len(parsed))

	// 1. 正常解析
	assert.Equal(t, "1-0", parsed[0].ID)
	assert.NoError(t, parsed[0].Err)
	assert.Equal(t, 1, parsed[0].Payload.ID)
	assert.Equal(t, "alice", parsed[0].Payload.Name)

	// 2. 缺失 payload
	assert.Equal(t, "2-0", parsed[1].ID)
	assert.Error(t, parsed[1].Err)
	assert.Contains(t, parsed[1].Err.Error(), "缺失 payload 字段")

	// 3. payload 类型非 string
	assert.Equal(t, "3-0", parsed[2].ID)
	assert.Error(t, parsed[2].Err)
	assert.Contains(t, parsed[2].Err.Error(), "非字符串类型")

	// 4. 反序列化失败
	assert.Equal(t, "4-0", parsed[3].ID)
	assert.Error(t, parsed[3].Err)
	assert.Contains(t, parsed[3].Err.Error(), "反序列化消息载荷失败")
}

func TestPublishOptions(t *testing.T) {
	opts := &publishOptions{
		extraValues: make(map[string]any),
	}

	WithMaxLen(5000)(opts)
	WithApproximate(false)(opts)
	WithPayloadKey("data")(opts)
	WithExtraValues(map[string]any{"trace_id": "xyz"})(opts)

	assert.Equal(t, int64(5000), opts.maxLen)
	assert.False(t, opts.approximate)
	assert.Equal(t, "data", opts.payloadKey)
	assert.Equal(t, "xyz", opts.extraValues["trace_id"])
}

func TestStreamQueue_AckEmpty(t *testing.T) {
	q := &streamQueue[demoPayload]{}
	err := q.Ack(context.Background(), "stream", "group")
	assert.NoError(t, err)
}
