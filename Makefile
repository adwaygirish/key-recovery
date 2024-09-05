# Makefile

# Variables
APP_NAME := myapp
SRC_DIR := src
BUILD_DIR := build

# Build the Go binary
build:
	go build

# Run the built binary
run: build
	./key_recovery

# Clean the build directory
clean:
	go clean
	rm -rf results*

testall:
	go test -v ./...

test:
	go test -v $(ARGS) -timeout 200m0s

# Define the run target with arguments
testfunc:
	go test -v $(ARGS1) -run $(ARGS2) -count=1 -timeout 200m0s

# Define a special target for handling arguments from the command line
# args-from-command-line:
# 	$(eval ARGS1 := $(word 2, $(MAKECMDGOALS)))
# 	$(eval ARGS2 := $(word 3, $(MAKECMDGOALS)))
# 	@true

# # Ensure the args-from-command-line target is executed before the run target
# testfunc: args-from-command-line