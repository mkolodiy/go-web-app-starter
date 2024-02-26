templ:
	templ generate

css:
	cd misc && pnpm css

run: templ css
	@go run cmd/main.go

run-watch:
	@air

build: templ css
	@go build -o bin/main cmd/main.go
