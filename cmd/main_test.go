package main

import (
	"testing"

	"go.uber.org/zap/zaptest"
)

func TestSetupRoutes(t *testing.T) {
	if err := setupRoutes(zaptest.NewLogger(t), "142.93.162.25"); err != nil {
		t.Fatalf("%v", err)
	}
}
