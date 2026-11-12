.PHONY: install test pcaps replay eval eval-claude demo clean

install:
	pip install -e ".[dev]"

test:
	pytest -q

pcaps:
	netsentry gen-pcaps data/pcaps

replay: pcaps
	netsentry replay data/scenarios.yaml

eval:
	netsentry eval --provider heuristic --out evals/results/heuristic.json

eval-claude:
	netsentry eval --provider anthropic --out evals/results/claude.json

demo: pcaps
	netsentry --config config/netsentry.yaml detect data/pcaps/udp_flood.pcap --out state/alerts.jsonl --baselines-out state/baselines.json
	netsentry --config config/netsentry.yaml respond state/alerts.jsonl
	netsentry --config config/netsentry.yaml triage state/alerts.jsonl --baselines state/baselines.json

clean:
	rm -rf data/pcaps state .pytest_cache
