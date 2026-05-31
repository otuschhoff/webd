package server

import "testing"

func TestValidate_FileHandlerAbortiveCloseRejected(t *testing.T) {
	cfg := &Config{Routes: []Route{{
		Path: "/static/",
		Handler: &Handler{
			Protocol:      "file",
			Path:          "/var/www/static",
			AbortiveClose: true,
		},
	}}}

	if err := Validate(cfg); err == nil {
		t.Fatal("Validate() expected error, got nil")
	}
}
