.PHONY: demo demo-down
demo:        ## run the end-to-end demo in a throwaway Docker Postgres
	./scripts/demo.sh
demo-down:   ## remove demo containers and volume (also runs automatically on exit)
	./scripts/demo.sh down
