package logger

import (
	"log"
	"os"
)

var (
	ErrorLogger *log.Logger
)

func init() {
	ErrorLogger = log.New(os.Stderr, "Error: ", log.Ltime)
}
