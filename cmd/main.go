package main

import (
	"context"
	"database/sql"
	"os"
	"os/signal"
	"task/service"
	"task/store"
)

func main() {
	if len(os.Args) < 2 {
		panic("signing key must be passed as an argument")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	//Create storagee
	connStr := "user=postgres dbname=postgres password=mysecretpassword sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
	if err := db.Ping(); err != nil {
		panic(err)
	}
	storage := store.New(db)
	if err := storage.Init(ctx); err != nil {
		panic(err)
	}

	//Create and run the service
	authService, err := service.New("localhost:8080", os.Args[1], storage)
	if err != nil {
		panic(err)
	}
	if err := authService.Run(ctx, "localhost:8080"); err != nil {
		panic(err)
	}
}
