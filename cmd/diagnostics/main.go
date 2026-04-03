package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	port := os.Getenv("DIAG_PORT")
	if port == "" {
		port = "8091"
	}

	authToken := os.Getenv("DIAG_AUTH_TOKEN")
	if authToken == "" {
		log.Println("WARNING: DIAG_AUTH_TOKEN is empty — all requests will be rejected with 403")
	}

	// Check ICMP availability at startup
	icmpAvailable := probeICMPAvailable()
	if icmpAvailable {
		log.Println("ICMP raw sockets available — ping will use ICMP")
	} else {
		log.Println("ICMP raw sockets unavailable — ping will use TCP fallback")
	}

	mux := registerHandlers(authToken, icmpAvailable)

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		WriteTimeout: 30 * time.Second,
		ReadTimeout:  10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown on SIGTERM
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		log.Printf("zovark-diagnostics listening on :%s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen error: %v", err)
		}
	}()

	<-done
	log.Println("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("shutdown error: %v", err)
	}
	log.Println("server stopped")
}
