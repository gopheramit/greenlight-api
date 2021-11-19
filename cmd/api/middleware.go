package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gopheramit/greenlight-api/internal/data"
	"github.com/gopheramit/greenlight-api/internal/validator"
)

func (app *application) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		defer func() {

			if err := recover(); err != nil {

				w.Header().Set("Connection", "close")

				app.serverErrorResponse(w, r, fmt.Errorf("%s", err))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (app *application) rateLimit(next http.Handler) http.Handler {

	type client struct {
		//limiter  *rate.Limiter
		lastSeen time.Time
	}
	var (
		mu sync.Mutex
	//	clients = make(map[string]*rate.Limiter)
	)
	go func() {
		for {
			time.Sleep(time.Minute)

			mu.Lock()

			//for ip, client := range clients {
			//	if time.Since(client.lastSeen) > 3*time.Minute {
			//		delete(clients, ip)
		}
		//}

		mu.Unlock()
		//}
	}()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		/*
			if app.config.limiter.enabled {
				ip, _, err := net.SplitHostPort(r.RemoteAddr)
				if err != nil {
					app.serverErrorResponse(w, r, err)
					return
				}
				mu.Lock()
				if _, found := clients[ip]; !found {
					clients[ip] = &client{
						// Use the requests-per-second and burst values from the config
						// struct.
						limiter: rate.NewLimiter(rate.Limit(app.config.limiter.rps), app.config.limiter.burst),
					}
				}
				clients[ip].lastSeen = time.Now()
				if !clients[ip].limiter.Allow() {
					mu.Unlock()
					app.rateLimitExceededResponse(w, r)
					return
				}
				mu.Unlock()
			}*/
		next.ServeHTTP(w, r)
	})
}

func (app *application) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Add("Vary", "Authorization")

		authorizationHeader := r.Header.Get("Authorization")

		if authorizationHeader == "" {
			r = app.contextSetUser(r, data.AnonymousUser)
			next.ServeHTTP(w, r)
			return
		}

		headerParts := strings.Split(authorizationHeader, " ")
		if len(headerParts) != 2 || headerParts[0] != "Bearer" {
			app.invalidAuthenticationTokenResponse(w, r)
			return
		}
		// Extract the actual authentication token from the header parts.
		token := headerParts[1]
		// Validate the token to make sure it is in a sensible format.
		v := validator.New()
		// If the token isn't valid, use the invalidAuthenticationTokenResponse()
		// helper to send a response, rather than the failedValidationResponse() helper
		// that we'd normally use.
		if data.ValidateTokenPlaintext(v, token); !v.Valid() {
			app.invalidAuthenticationTokenResponse(w, r)
			return
		}
		// Retrieve the details of the user associated with the authentication token,
		// again calling the invalidAuthenticationTokenResponse() helper if no
		// matching record was found. IMPORTANT: Notice that we are using
		// ScopeAuthentication as the first parameter here.
		user, err := app.models.Users.GetForToken(data.ScopeAuthentication, token)
		if err != nil {
			switch {
			case errors.Is(err, data.ErrRecordNotFound):
				app.invalidAuthenticationTokenResponse(w, r)
			default:
				app.serverErrorResponse(w, r, err)
			}
			return
		}
		// Call the contextSetUser() helper to add the user information to the request
		// context.
		r = app.contextSetUser(r, user)
		// Call the next handler in the chain.
		next.ServeHTTP(w, r)
	})
}
