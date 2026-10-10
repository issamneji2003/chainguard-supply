.PHONY: all test build pipeline clean

all: pipeline

test:
	PYTHONPATH=. pytest tests/

build:
	docker build -t chainguard-app:latest .

pipeline: test build
	python run_pipeline.py

clean:
	rm -rf reports/
	docker rmi chainguard-app:latest || true