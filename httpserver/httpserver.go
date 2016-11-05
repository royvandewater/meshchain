package server

// HTTPServer provides an HTTP API for the meshbluchain engine
type HTTPServer struct {
	port int
}

// New constructs a new instance of an HTTPServer
func New(port int) *HTTPServer {
	return &HTTPServer{port: port}
}
