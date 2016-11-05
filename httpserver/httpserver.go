package httpserver

import (
	"fmt"
	"net/http"

	"github.com/gocraft/web"
	"github.com/royvandewater/meshchain/httpserver/handlers"
)

// HTTPServer provides an HTTP API for the meshbluchain engine
type HTTPServer struct {
	port int
}

// New constructs a new instance of an HTTPServer
func New(port int) *HTTPServer {
	return &HTTPServer{port: port}
}

// Run the server
func (server *HTTPServer) Run() error {
	router := web.New(struct{}{}).
		Middleware(web.LoggerMiddleware).
		Middleware(web.ShowErrorsMiddleware).
		Get("/records/:uuid", handlers.GetRecord).
		Post("/records", handlers.CreateRecord)

	host := fmt.Sprintf("0.0.0.0:%v", server.port)
	return http.ListenAndServe(host, router)
}
