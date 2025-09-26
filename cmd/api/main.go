package main

import (
	"log"
	"net/http"

	"github.com/temo927/SIWE-Auth-API-Go-/internal/config"
	"github.com/temo927/SIWE-Auth-API-Go-/internal/httpx"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	router := httpx.NewRouter(cfg)

	log.Println("listening on :8080")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatal(err)
	}
}
