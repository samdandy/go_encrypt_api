package handlers

import (
	"github.com/go-chi/chi"
)

func Handler(r *chi.Mux) {
	r.Route("/GenerateKeyPair", func(r chi.Router) {
		r.Get("/", GenerateKeyPairHandler)
	})
	r.Route("/EncryptMessage", func(r chi.Router) {
		r.Post("/", EncryptMessageHandler)
	})
	r.Route("/DecryptMessage", func(r chi.Router) {
		r.Post("/", DecryptMessageHandler)
	})

}
