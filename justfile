set dotenv-load

# alias
alias r := run

default:
    @just --list

# database 
create-migration name:
	go tool goose -dir database/migrations sqlite3 ./mithlond-ce.db create {{name}} sql

fix-migrations:
	go tool goose -dir database/migrations sqlite3 ./mithlond-ce.db fix

new-migration name: 
	just create-migration {{name}}
	just fix-migrations

up-migrations:
	go tool goose -dir database/migrations sqlite3 ./mithlond-ce.db up

# sqlc
compile-queries:
	go tool sqlc -f ./database/sqlc.yaml compile

generate-queries:
	go tool sqlc -f ./database/sqlc.yaml generate

compile-generate-queries: compile-queries generate-queries

# server
live-server:
	go tool air -build.cmd "go build -o tmp/bin/main cmd/app/main.go" -build.bin "tmp/bin/main" -build.exclude_dir "node_modules" -build.include_ext "go,css,js" -build.stop_on_error false -misc.clean_on_exit true

# setup
setup platform:
	#!/usr/bin/env bash
	set -euo pipefail
	
	mkdir -p bin
	
	case "{{platform}}" in
		"mac"|"darwin")
			ARCH="macos-x64"
			;;
		"linux")
			ARCH="linux-x64"
			;;
		"windows")
			ARCH="windows-x64.exe"
			;;
		*)
			echo "Unsupported platform: {{platform}}"
			echo "Supported platforms: mac, linux, windows"
			exit 1
			;;
	esac
	
	URL="https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-$ARCH"
	
	echo "Downloading latest Tailwind CLI for {{platform}}..."
	curl -sL "$URL" -o bin/tailwindcli
	chmod +x bin/tailwindcli
	echo "Tailwind CLI downloaded to bin/tailwindcli"

# generation
live-templ:
	go tool air -build.cmd "go tool templ generate --watch" -build.include_ext "templ" -build.bin "true" -build.include_dir "views" -build.exclude_regex "_templ.go"

live-tailwind:
	./bin/tailwindcli -i ./css/base.css -o ./assets/css/tw.css --watch

[parallel]
run: live-tailwind live-templ live-server 

# code quality
golangci:
	golangci-lint run

vet:
	@go vet ./...

golines:
	@golines -w -m 100 controllers models router router/routes 

move-boot:
	go build -o boot cmd/boot/main.go  && scp -i ~/.ssh/test_key ./boot root@91.98.31.175:/root
