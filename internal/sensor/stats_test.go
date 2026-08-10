package sensor

import (
	"context"
	"testing"
	"time"
)

func TestTryEmit_DropsWhenFull(t *testing.T) {
	before := Global.ChannelDrop.Load()
	ch := make(chan Event) // unbuffered → default select path when no receiver
	ctx := context.Background()
	if TryEmit(ctx, ch, Event{Kind: KindExec}) {
		t.Fatal("expected drop on full/unbuffered channel without receiver")
	}
	if Global.ChannelDrop.Load() != before+1 {
		t.Fatalf("ChannelDrop=%d want %d", Global.ChannelDrop.Load(), before+1)
	}
}

func TestTryEmit_SendsWhenBuffered(t *testing.T) {
	ch := make(chan Event, 1)
	if !TryEmit(context.Background(), ch, Event{Kind: KindOpenat, PID: 7}) {
		t.Fatal("expected send")
	}
	ev := <-ch
	if ev.Kind != KindOpenat || ev.PID != 7 {
		t.Fatalf("%+v", ev)
	}
}

func TestDebouncer(t *testing.T) {
	d := NewDebouncer(50 * time.Millisecond)
	ev := Event{Kind: KindExec, PID: 1, Comm: "bash"}
	if !d.Allow(ev) {
		t.Fatal("first allow")
	}
	if d.Allow(ev) {
		t.Fatal("should debounce")
	}
	time.Sleep(60 * time.Millisecond)
	if !d.Allow(ev) {
		t.Fatal("should allow after window")
	}
	if NewDebouncer(0) != nil {
		t.Fatal("zero window should disable")
	}
}

func TestOpen_UnknownBackend(t *testing.T) {
	_, err := Open(context.Background(), "nope")
	if err == nil {
		t.Fatal("expected error")
	}
}
