package kafka

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/IBM/sarama"
)

// Message is the structure expected from Kafka.
type message struct {
	Type    string            `json:"type"`    // e.g., "activation_email", "reset_phone"
	To      string            `json:"to"`      // email or phone
	Subject string            `json:"subject"` // only for email
	Macros  map[string]string `json:"macros"`  // template variables
}

type producer struct {
	appName            string
	producer           sarama.SyncProducer
	verificationLink   string
	topicVerification  string
	passwordResetLink  string
	topicPasswordReset string
}

// New initializes a new Kafka producer with client ID, version, and retry configuration.
// It returns a Messager adapter for publishing email-related events.
func New(appName string, brokers []string, clientID, version string, retryMax int) (*producer, error) {
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
	return &producer{
		appName:  appName,
		producer: producer,
	}, nil
}

// RegisterPasswordReset sets the Kafka topic and link for password reset emails.
func (p *producer) RegisterPasswordReset(topic, link string) {
	p.topicPasswordReset = topic
	p.passwordResetLink = link
}

// RegisterVerification sets the Kafka topic and link for verification emails.
func (p *producer) RegisterVerification(topic, link string) {
	p.topicVerification = topic
	p.verificationLink = link
}

// PublishVerification sends a user verify email event to the Kafka topic.
func (p *producer) PublishVerificationEmail(toAddress, subject, name, token string) error {

	link := strings.Replace(p.verificationLink, "{{token}}", token, 1)

	payload := message{
		Type:    "verification-email",
		To:      toAddress,
		Subject: subject,
		Macros: map[string]string{
			"name":    name,
			"link":    link,
			"appName": p.appName,
		},
	}

	return p.publish(p.topicVerification, toAddress, payload)
}

// PublishPasswordResetEmail sends a password reset email event to the Kafka topic.
func (p *producer) PublishPasswordResetEmail(toAddress, subject, name, token string) error {
	link := strings.Replace(p.verificationLink, "{{token}}", token, 1)

	payload := message{
		Type:    "password-reset-email",
		To:      toAddress,
		Subject: subject,
		Macros: map[string]string{
			"name":    name,
			"link":    link,
			"appName": p.appName,
		},
	}

	return p.publish(p.topicPasswordReset, toAddress, payload)
}

// PublishVerificationPhone sends a user verify phone event to the Kafka topic.
func (p *producer) PublishVerificationPhone(phone, name, token string) error {

	payload := message{
		Type: "verification-phone",
		To:   phone,
		Macros: map[string]string{
			"name":    name,
			"token":   token,
			"appName": p.appName,
		},
	}

	return p.publish(p.topicVerification, phone, payload)
}

// PublishPasswordResetPhone sends a password reset phone event to the Kafka topic.
func (p *producer) PublishPasswordResetPhone(phone, name, token string) error {
	payload := message{
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
func (p *producer) publish(topic string, key string, payload any) error {
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
