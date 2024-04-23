package internal

import (
	"net/url"

	formUtils "github.com/go-playground/form/v4"
)

var decoder *formUtils.Decoder

type RegisterForm struct {
	FirstName string `form:"firstName" validate:"required"`
	LastName  string `form:"lastName" validate:"required"`
	Email     string `form:"email" validate:"required,email"`
	Password  string `form:"password" validate:"required"`
}

type LoginForm struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required"`
}

func PopulateForm[TForm any](form TForm, values url.Values) (TForm, error) {
	decoder = formUtils.NewDecoder()
	err := decoder.Decode(&form, values)
	return form, err
}
