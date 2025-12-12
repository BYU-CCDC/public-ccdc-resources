package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/hibiken/asynq"
)

type Event struct {
	RuleName string
	Data     map[string]interface{}
}

// Implement the list.Item interface
func (e Event) Title() string       { return e.RuleName }
func (e Event) Description() string { return fmt.Sprintf("Data: %v", e.Data) }
func (e Event) FilterValue() string { return e.RuleName }

type eventMsg struct {
	Event Event
}

type model struct {
	list    list.Model
	eventCh chan eventMsg // Channel for receiving events
}

var (
	client *asynq.Client
	srv    *asynq.Server
)

func handleDetectedEvent(ctx context.Context, t *asynq.Task, eventCh chan eventMsg) error {
	var eventData map[string]interface{}
	if err := json.Unmarshal(t.Payload(), &eventData); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %v", err)
	}

	ruleName := "unknown"
	if rn, ok := eventData["rule_name"].(string); ok {
		ruleName = rn
	}

	event := Event{RuleName: ruleName, Data: eventData}
	eventCh <- eventMsg{Event: event} // Send the event to the channel
	return nil
}

func initialModel(eventCh chan eventMsg) *model {
	items := []list.Item{}
	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Detected Events"
	return &model{list: l, eventCh: eventCh}
}

func (m *model) Init() tea.Cmd {
	return nil
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case eventMsg:
		m.list.InsertItem(0, msg.Event)
	case tea.KeyMsg:
		switch msg.String() {
		case "up":
			m.list.CursorUp()
		case "down":
			m.list.CursorDown()
		case "delete":
			index := m.list.Index()
			if index >= 0 {
				m.list.RemoveItem(index)
			}
		case "q", "ctrl+c":
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m *model) View() string {
	return m.list.View()
}

func main() {
	client = asynq.NewClient(asynq.RedisClientOpt{Addr: "localhost:6379"})
	defer client.Close()

	srv = asynq.NewServer(
		asynq.RedisClientOpt{Addr: "localhost:6379"},
		asynq.Config{Concurrency: 10},
	)
	defer srv.Shutdown()

	// Channel for sending events to the Bubble Tea program
	eventCh := make(chan eventMsg)

	mux := asynq.NewServeMux()
	mux.HandleFunc("TypeDetectedEvent", func(ctx context.Context, t *asynq.Task) error {
		return handleDetectedEvent(ctx, t, eventCh)
	})

	go func() {
		if err := srv.Run(mux); err != nil {
			log.Fatalf("Could not run server: %v", err)
		}
	}()

	// Start the Bubble Tea program
	p := tea.NewProgram(initialModel(eventCh))
	go func() {
		for event := range eventCh {
			p.Send(event) // Send events received on the channel to the Bubble Tea program
		}
	}()

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Could not start Bubble Tea: %v", err)
		os.Exit(1)
	}
}