package producer

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/IBM/sarama"
)

type mockSyncProducer struct {
	sentMessages []*sarama.ProducerMessage
	err          error
}

func (m *mockSyncProducer) SendMessage(msg *sarama.ProducerMessage) (partition int32, offset int64, err error) {
	m.sentMessages = append(m.sentMessages, msg)
	return 0, 0, m.err
}

func (m *mockSyncProducer) SendMessages(msgs []*sarama.ProducerMessage) error { return m.err }
func (m *mockSyncProducer) Close() error                                      { return nil }
func (m *mockSyncProducer) TxnStatus() sarama.ProducerTxnStatusFlag {
	return sarama.ProducerTxnFlagReady
}
func (m *mockSyncProducer) IsTransactional() bool { return false }
func (m *mockSyncProducer) BeginTxn() error       { return nil }
func (m *mockSyncProducer) CommitTxn() error      { return nil }
func (m *mockSyncProducer) AbortTxn() error       { return nil }
func (m *mockSyncProducer) AddOffsetsToTxn(map[string][]*sarama.PartitionOffsetMetadata, string) error {
	return nil
}
func (m *mockSyncProducer) AddMessageToTxn(*sarama.ConsumerMessage, string, *string) error {
	return nil
}

func TestPublishVerificationEmail(t *testing.T) {
	mock := &mockSyncProducer{}
	p := &producer{appName: "utils", producer: mock, topicVerification: "verify-topic"}

	err := p.PublishVerificationEmail("user@example.com", "Verify", "Jane", "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.sentMessages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(mock.sentMessages))
	}

	msg := mock.sentMessages[0]
	if msg.Topic != "verify-topic" {
		t.Fatalf("unexpected topic: %s", msg.Topic)
	}

	encoded, err := msg.Value.Encode()
	if err != nil {
		t.Fatalf("unexpected encode error: %v", err)
	}

	var got message
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("unexpected payload unmarshal error: %v", err)
	}

	if got.Type != "verification-email" || got.Macros["appName"] != "utils" {
		t.Fatalf("unexpected payload: %+v", got)
	}
}

func TestPublishErrors(t *testing.T) {
	t.Run("marshal error", func(t *testing.T) {
		p := &producer{producer: &mockSyncProducer{}}
		err := p.publish("topic", "k", func() {})
		if err == nil {
			t.Fatal("expected marshal error")
		}
	})

	t.Run("send error", func(t *testing.T) {
		sendErr := errors.New("send failed")
		p := &producer{producer: &mockSyncProducer{err: sendErr}}
		err := p.publish("topic", "k", map[string]string{"x": "y"})
		if err == nil {
			t.Fatal("expected send error")
		}
	})
}
