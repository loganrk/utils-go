package kafka

import (
	"encoding/json"
	"fmt"

	"github.com/IBM/sarama"
)

type produceMessager struct {
	appName            string
	producer           sarama.SyncProducer
	topicVerification  string
	topicPasswordReset string
}

// New initializes a new Kafka producer with client ID, version, and retry configuration.
// It returns a Messager adapter for publishing email-related events.
func NewUserProducer(appName string, brokers []string, verificationTopic, passwordResetTopic, clientID, version string, retryMax int) (*produceMessager, error) {
	kConfig := sarama.NewConfig()

	// Set client ID for Kafka tracing and logging
	kConfig.ClientID = clientID

	// Parse and apply Kafka protocol version
	parsedVersion, err := sarama.ParseKafkaVersion(version)
	if err != nil {
		return nil, fmt.Errorf("invalid Kafka version: %w", err)
	}
	kConfig.Version = parsedVersion

	// Enable delivery reporting and retry settings
	kConfig.Producer.Return.Successes = true
	kConfig.Producer.Retry.Max = retryMax
	// Create Kafka producer
	producer, err := sarama.NewSyncProducer(brokers, kConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kafka producer: %w", err)
	}

	// Return the Messager instance
	return &produceMessager{
		appName:            appName,
		producer:           producer,
		topicVerification:  verificationTopic,
		topicPasswordReset: passwordResetTopic,
	}, nil
}

// PublishVerification sends a user verify email event to the Kafka topic.
func (p *produceMessager) PublishVerificationEmail(toAddress, subject, name, token string) error {

	payload := struct {
		Type    string            `json:"type"`
		To      string            `json:"to"`
		Subject string            `json:"subject"`
		Macros  map[string]string `json:"macros"`
	}{
		Type:    "verification-email",
		To:      toAddress,
		Subject: subject,
		Macros: map[string]string{
			"name":    name,
			"token":   token,
			"appName": p.appName,
		},
	}

	return p.publish(p.topicVerification, toAddress, payload)
}

// PublishPasswordResetEmail sends a password reset email event to the Kafka topic.
func (k *produceMessager) PublishPasswordResetEmail(toAddress, subject, name, token string) error {
	payload := struct {
		Type    string            `json:"type"`
		To      string            `json:"to"`
		Subject string            `json:"subject"`
		Macros  map[string]string `json:"macros"`
	}{
		Type:    "password-reset-email",
		To:      toAddress,
		Subject: subject,
		Macros: map[string]string{
			"name":    name,
			"token":   token,
			"appName": k.appName,
		},
	}

	return k.publish(k.topicPasswordReset, toAddress, payload)
}

// PublishVerificationPhone sends a user verify phone event to the Kafka topic.
func (k *produceMessager) PublishVerificationPhone(phone, name, token string) error {

	payload := struct {
		Type   string            `json:"type"`
		To     string            `json:"to"`
		Macros map[string]string `json:"macros"`
	}{
		Type: "verification-phone",
		To:   phone,
		Macros: map[string]string{
			"name":    name,
			"token":   token,
			"appName": k.appName,
		},
	}

	return k.publish(k.topicVerification, phone, payload)
}

// PublishPasswordResetPhone sends a password reset phone event to the Kafka topic.
func (p *produceMessager) PublishPasswordResetPhone(phone, name, token string) error {
	payload := struct {
		Type   string            `json:"type"`
		To     string            `json:"to"`
		Macros map[string]string `json:"macros"`
	}{
		Type: "password-reset-email",
		To:   phone,
		Macros: map[string]string{
			"name":    name,
			"token":   token,
			"appName": p.appName,
		},
	}

	return p.publish(p.topicPasswordReset, phone, payload)
}

// publish marshals the payload and sends it to the specified Kafka topic with the given key.
func (p *produceMessager) publish(topic string, key string, payload any) error {
	value, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal message payload: %w", err)
	}

	msg := &sarama.ProducerMessage{
		Topic: topic,
		Key:   sarama.StringEncoder(key),
		Value: sarama.ByteEncoder(value),
	}

	_, _, err = p.producer.SendMessage(msg)
	if err != nil {
		return fmt.Errorf("failed to send Kafka message: %w", err)
	}

	return nil
}
