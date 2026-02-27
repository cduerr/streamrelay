package hub

import (
	"log/slog"
	"testing"
)

func newTestHub(bufferSize int, policy string) *Hub {
	return New(0, 0, bufferSize, policy, slog.Default())
}

func registerTestClient(t *testing.T, h *Hub, identity string) *Client {
	t.Helper()
	c := h.NewClient(identity, "test", nil, "")
	if err := h.Register(c); err != nil {
		t.Fatalf("register: %v", err)
	}
	return c
}

func TestSendDelivery(t *testing.T) {
	h := newTestHub(8, "drop_newest_message")
	c := registerTestClient(t, h, "user1")

	h.Send("user1", []byte("hello"))

	select {
	case msg := <-c.Send:
		if string(msg) != "hello" {
			t.Fatalf("got %q, want %q", msg, "hello")
		}
	default:
		t.Fatal("expected message on send channel")
	}

	s := h.Stats()
	if s.MessagesDropped != 0 || s.ClientsDropped != 0 {
		t.Fatalf("expected zero drops, got messages=%d clients=%d", s.MessagesDropped, s.ClientsDropped)
	}
}

func TestSendDropsMessage_DropNewest(t *testing.T) {
	h := newTestHub(1, "drop_newest_message")
	c := registerTestClient(t, h, "user1")

	// Fill the buffer.
	h.Send("user1", []byte("msg1"))
	// This should be dropped.
	h.Send("user1", []byte("msg2"))

	s := h.Stats()
	if s.MessagesDropped != 1 {
		t.Fatalf("expected 1 message dropped, got %d", s.MessagesDropped)
	}
	if s.ClientsDropped != 0 {
		t.Fatalf("expected 0 clients dropped, got %d", s.ClientsDropped)
	}
	// Client should still be registered.
	if s.Connections != 1 {
		t.Fatalf("expected 1 connection, got %d", s.Connections)
	}

	// Original message still deliverable.
	msg := <-c.Send
	if string(msg) != "msg1" {
		t.Fatalf("got %q, want %q", msg, "msg1")
	}
}

func TestSendDropsClient_DropClient(t *testing.T) {
	h := newTestHub(1, "drop_client")
	c := registerTestClient(t, h, "user1")

	// Fill the buffer.
	h.Send("user1", []byte("msg1"))
	// This should trigger client disconnect.
	h.Send("user1", []byte("msg2"))

	s := h.Stats()
	if s.ClientsDropped != 1 {
		t.Fatalf("expected 1 client dropped, got %d", s.ClientsDropped)
	}
	if s.MessagesDropped != 0 {
		t.Fatalf("expected 0 messages dropped, got %d", s.MessagesDropped)
	}
	// Client should be unregistered.
	if s.Connections != 0 {
		t.Fatalf("expected 0 connections, got %d", s.Connections)
	}

	// Client's done channel should be closed.
	select {
	case <-c.Done():
	default:
		t.Fatal("expected client done channel to be closed")
	}
}

func TestStatsCountersCumulative(t *testing.T) {
	h := newTestHub(1, "drop_newest_message")

	for i := 0; i < 5; i++ {
		c := registerTestClient(t, h, "user1")
		// Fill buffer.
		h.Send("user1", []byte("fill"))
		// Drop.
		h.Send("user1", []byte("drop"))
		// Drain and unregister so next iteration starts clean.
		<-c.Send
		h.Unregister(c)
	}

	s := h.Stats()
	if s.MessagesDropped != 5 {
		t.Fatalf("expected 5 cumulative drops, got %d", s.MessagesDropped)
	}
}
