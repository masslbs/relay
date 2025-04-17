// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/getsentry/sentry-go"
	sentryhttp "github.com/getsentry/sentry-go/http"
)

const sentryFlushTimeout = 2 * time.Second

func init() {
	sentryDsn := os.Getenv("SENTRY_DSN")
	if sentryDsn == "" {
		return
	}

	err := sentry.Init(sentry.ClientOptions{
		Dsn:         sentryDsn,
		Release:     "relay-" + release,
		Environment: mustGetEnvString("SENTRY_ENVIRONMENT"),
	})
	check(err)
}

// wraps the passed handler such that panics are reported and the reporter tool can be unboxed in handlers via http.Request.Context
func sentrySetupHTTPHandler(handler http.Handler) http.Handler {
	// middleware that attaches area=http to all thrown exceptions
	addTags := func(handler http.Handler) http.HandlerFunc {
		return func(rw http.ResponseWriter, r *http.Request) {
			if hub := sentry.GetHubFromContext(r.Context()); hub != nil {
				hub.Scope().SetTag("area", "http")
			}
			handler.ServeHTTP(rw, r)
		}
	}
	return sentryhttp.New(sentryhttp.Options{Repanic: true}).Handle(addTags(handler))
}

func sentryRecover() {
	v := recover()
	if v != nil {
		if err, ok := v.(error); ok {
			localHub := sentry.CurrentHub().Clone()
			localHub.ConfigureScope(func(scope *sentry.Scope) {
				scope.SetTag("area", "db.run")
			})
			localHub.CaptureException(err)
			sentry.Flush(sentryFlushTimeout)
		} else {
			log("sentryRecover: unknown panic type: %T", v)
		}
		// repanic the original value as if it wasnt recovered.
		// this adds adds two frames to the stack trace.
		panic(v)
	}
}

// test handler that can be used to test sentry integration
func sentryTestHandler() func(http.ResponseWriter, *http.Request) {
	log("server.sentryTestHandler")
	return func(w http.ResponseWriter, _ *http.Request) {
		log("server.sentryTestHandler.start")

		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
		log("server.sentryTestHandler.panic")
		err := errors.New("Bang")
		panic(err)
	}
}

/* TODO snippets
hub := sentry.CurrentHub().Clone()
hub.Scope().SetExtra("userId", hex.EncodeToString(...))
hub.Scope().SetExtra("eventId", hex.EncodeToString(...))
hub.CaptureException(err)

*/
