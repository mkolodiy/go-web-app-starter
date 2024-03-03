package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	en_translations "github.com/go-playground/validator/v10/translations/en"
	"github.com/google/uuid"
	"github.com/mkolodiy/go-web-app-starter/internal/components"
	"github.com/mkolodiy/go-web-app-starter/internal/db"
	"golang.org/x/crypto/bcrypt"
)

var (
	uni      *ut.UniversalTranslator
	validate *validator.Validate
)

type UserData struct {
	FirstName string `json:"firstName" validate:"required"`
	LastName  string `json:"lastName" validate:"required"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required"`
}

func main() {
	ctx := context.Background()

	fmt.Println("start")
	sqlDb, err := db.Setup(ctx)
	if err != nil {
		fmt.Println(err)
	}

	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fmt.Println("remove sessions")
				err := db.CleanUpSessions(ctx, sqlDb)
				if err != nil {
					log.Default().Println(err)
				}
			}
		}
	}()

	en := en.New()
	uni = ut.New(en, en)
	trans, _ := uni.GetTranslator("en")
	validate = validator.New(validator.WithRequiredStructEnabled())
	en_translations.RegisterDefaultTranslations(validate, trans)

	user, err := db.GetUserByEmail(sqlDb, "john@doe.com")
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(user)

	r := chi.NewRouter()

	r.Handle("/assets/*", http.StripPrefix("/assets/", http.FileServer(http.Dir("assets"))))

	// r.Post("/validate/firstName", func(w http.ResponseWriter, r *http.Request) {
	// 	firstName := r.FormValue("firstName")
	// 	fmt.Println(firstName)

	// 	errs := validate.Struct(UserData{
	// 		FirstName: firstName,
	// 	})

	// 	if errs != nil {
	// 		valErrs := errs.(validator.ValidationErrors)
	// 		for _, valErr := range valErrs {
	// 			if valErr.Field() == "FirstName" {
	// 				components.RegisterFirstName(components.RegisterFirstNameProps{
	// 					ErrorMessage: valErr.Translate(trans),
	// 				}).Render(r.Context(), w)
	// 				return
	// 			}
	// 		}
	// 	}

	// 	components.RegisterFirstName(components.RegisterFirstNameProps{
	// 		Value: firstName,
	// 	}).Render(r.Context(), w)
	// })

	r.Group(func(r chi.Router) {
		// Process with the request if
		// - the cookie is not present
		// - the cookie is not valid or the value is empty
		// - the session is not in the DB
		// - the session is expired
		// - there are general errors
		// otherwise redirect to the homepage
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sessionCookie, err := r.Cookie("session_id")
				if errors.Is(err, http.ErrNoCookie) {
					log.Default().Println("session cookie not there show login page")
					fmt.Println("session cookie not there show login page")
					next.ServeHTTP(w, r)
					return
				}
				if err != nil {
					fmt.Println(err)
					// TODO: Show a toast message in the FE
					return
				}

				err = sessionCookie.Valid()
				if err != nil || sessionCookie.Value == "" {
					log.Default().Println("session cookie is not valid")
					next.ServeHTTP(w, r)
					return
				}

				sessionID := sessionCookie.Value
				session, err := db.GetSession(sqlDb, sessionID)
				if errors.Is(err, sql.ErrNoRows) {
					fmt.Println(err)
					next.ServeHTTP(w, r)
					return
				}
				if err != nil {
					fmt.Println(err)
				}

				fmt.Println("session", session)
				if session.Expires.Before(time.Now()) {
					// Remove sessions from DB
					fmt.Println("session not valid anymore")
					err = db.RemoveSession(sqlDb, sessionID)
					if err != nil {
						fmt.Println(err)
					}
					next.ServeHTTP(w, r)
					return
				}

				http.Redirect(w, r, "/", http.StatusFound)
			})
		})

		r.Get("/register", templ.Handler(components.Register()).ServeHTTP)
		r.Post("/register", func(w http.ResponseWriter, r *http.Request) {
			userData := UserData{
				FirstName: r.FormValue("firstName"),
				LastName:  r.FormValue("lastName"),
				Email:     r.FormValue("email"),
				Password:  r.FormValue("password"),
			}

			isHTMXRequest := r.Header.Get("HX-Request") == "true"

			errs := validate.Struct(userData)

			if errs != nil {
				valErrs := errs.(validator.ValidationErrors)
				fmtErrs := make(map[string]string, 0)
				for _, valErr := range valErrs {
					fmtErrs[valErr.Field()] = valErr.Translate(trans)

				}
				fields := []templ.Component{
					components.RegisterFirstName(components.RegisterFirstNameProps{
						Value:        userData.FirstName,
						ErrorMessage: fmtErrs["FirstName"],
					}),
					components.RegisterLastName(components.RegisterLastNameProps{
						Value:        userData.LastName,
						ErrorMessage: fmtErrs["LastName"],
					}),
					components.RegisterEmail(components.RegisterEmailProps{
						Value:        userData.Email,
						ErrorMessage: fmtErrs["Email"],
					}),
					components.RegisterPassword(components.RegisterPasswordProps{
						Value:        userData.Password,
						ErrorMessage: fmtErrs["Password"],
					}),
				}
				form := components.RegisterForm(fields...)

				if isHTMXRequest {
					form.Render(r.Context(), w)
				} else {
					components.Register(form).Render(r.Context(), w)
				}

				return
			}

			// Check if user already exists
			// TODO

			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userData.Password), bcrypt.DefaultCost)
			// TODO
			if err != nil {
				fmt.Println(err)
			}

			userID, err := db.InsertUser(sqlDb, db.User{
				FirstName: userData.FirstName,
				LastName:  userData.LastName,
				Email:     userData.Email,
				Password:  string(hashedPassword),
			})
			// TODO
			if err != nil {
				fmt.Println("SOME ERROR", err)
				components.Toast(components.ToastProps{Message: "Something went wrong", Type: components.ToastError}).Render(r.Context(), w)
				return
			}

			// Session
			sessionID := uuid.NewString()
			expires := time.Now().Add(1 * time.Minute)
			err = db.InsertSession(sqlDb, db.Session{
				SessionID: sessionID,
				UserID:    userID,
				Expires:   expires,
			})
			// TODO
			if err != nil {
				fmt.Println(err)
			}
			sessionCookie := http.Cookie{
				Name:     "session_id",
				Value:    sessionID,
				Expires:  expires,
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			}
			w.Header().Add("Set-Cookie", sessionCookie.String())

			if isHTMXRequest {
				w.Header().Set("HX-Redirect", "/login")
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
		})

		r.Get("/login", templ.Handler(components.Login()).ServeHTTP)

		r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
			fmt.Println("/login")
			isHTMXRequest := r.Header.Get("HX-Request") == "true"

			email := r.FormValue("email")
			password := r.FormValue("password")

			fmt.Println("login post")
			fmt.Println(email, password)

			user, err := db.GetUserByEmail(sqlDb, email)
			if err != nil {
				fmt.Println(err)
				http.Redirect(w, r, "/login", http.StatusUnauthorized)
				return
			}

			err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
			if err != nil {
				fmt.Println(err)
				http.Redirect(w, r, "/login", http.StatusUnauthorized)
				return
			}

			// Session
			sessionID := uuid.NewString()
			expires := time.Now().Add(30 * time.Second)
			err = db.InsertSession(sqlDb, db.Session{
				SessionID: sessionID,
				UserID:    user.ID,
				Expires:   expires,
			})
			// TODO
			if err != nil {
				fmt.Println(err)
			}
			sessionCookie := &http.Cookie{
				Name:     "session_id",
				Value:    sessionID,
				Expires:  expires,
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			}
			http.SetCookie(w, sessionCookie)

			if isHTMXRequest {
				w.Header().Set("HX-Redirect", "/")
			} else {
				http.Redirect(w, r, "/", http.StatusFound)
			}
		})
	})

	r.Group(func(r chi.Router) {
		// Redirect to the login page if
		// - the cookie is not present
		// - the cookie is not valid or is empty
		// - the session is not in the DB
		// - the session is expired
		// - there are general errors
		// otherwise proceed with the request
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sessionCookie, err := r.Cookie("session_id")
				if errors.Is(err, http.ErrNoCookie) {
					fmt.Println("redirect ####")
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
				if err != nil {
					fmt.Println(err)
					// TODO: Show a toast with an error in the UI
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
				err = sessionCookie.Valid()
				if err != nil || sessionCookie.Value == "" {
					fmt.Println(err)
					fmt.Println("redirect ####")
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}

				sessionID := sessionCookie.Value
				session, err := db.GetSession(sqlDb, sessionID)
				if errors.Is(err, sql.ErrNoRows) {
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
				if err != nil {
					// TODO: Show a toast with an error in the UI
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}

				if session.Expires.Before(time.Now()) {
					err = db.RemoveSession(sqlDb, sessionID)
					if err != nil {
						log.Default().Println(err)
					}
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}

				next.ServeHTTP(w, r)
			})
		})

		r.Get("/", templ.Handler(components.Home()).ServeHTTP)

		r.Post("/logout", func(w http.ResponseWriter, r *http.Request) {
			isHTMXRequest := r.Header.Get("HX-Request") == "true"

			sessionCookie, err := r.Cookie("session_id")
			if err != nil {
				fmt.Println(err)
			}

			err = db.RemoveSession(sqlDb, sessionCookie.Value)
			if err != nil {
				fmt.Println(err)
			}

			sessionCookie = &http.Cookie{
				Name:     "session_id",
				MaxAge:   -1,
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			}
			http.SetCookie(w, sessionCookie)

			fmt.Println("/logout", isHTMXRequest)
			if isHTMXRequest {
				w.Header().Set("HX-Redirect", "/login")
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
		})
	})

	srv := &http.Server{
		Addr:    ":3000",
		Handler: r,
		BaseContext: func(l net.Listener) context.Context {
			return ctx
		},
	}
	srv.ListenAndServe()
}
