.PHONY: install setup data train run test lint clean help

help:
	@echo ""
	@echo "  cybersecurity-attack-path-prediction-using-gnn"
	@echo "  ─────────────────────────────────────────────"
	@echo "  make install   Install all dependencies"
	@echo "  make setup     Install + generate data"
	@echo "  make data      Generate synthetic dataset"
	@echo "  make train     Train the GAT model"
	@echo "  make run       Launch the dashboard"
	@echo "  make test      Run unit tests"
	@echo "  make lint      Run linter (ruff + black)"
	@echo "  make clean     Remove generated artifacts"
	@echo ""

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements-dev.txt

setup: install data

data:
	python data/generate_synthetic_data.py --graphs 500 --min-nodes 20 --max-nodes 80

train:
	python gnn/train_gnn.py --epochs 200 --hidden 64 --heads 8

run:
	streamlit run dashboard/app.py

test:
	pytest tests/ -v --cov=. --cov-report=term-missing

lint:
	ruff check . && black --check .

format:
	black . && ruff check --fix .

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
	rm -f gnn_model.pt gnn_dataset.pt; \
	find . -name "*.pyc" -delete
