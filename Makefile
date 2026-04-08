.PHONY: help up down logs status clean rules test attack hunt

help:
	@echo "SOC Lab v2 - common operations"
	@echo ""
	@echo "  make up        Bring up the full stack"
	@echo "  make down      Stop the stack (volumes preserved)"
	@echo "  make clean     Stop and wipe all volumes"
	@echo "  make status    Show service health"
	@echo "  make logs      Tail Wazuh manager logs"
	@echo "  make rules     Compile Sigma -> Wazuh and reload manager"
	@echo "  make test      Run detection unit tests"
	@echo "  make attack    Run full adversary emulation chain"
	@echo "  make hunt      Launch threat hunting Jupyter notebook"

up:
	docker compose up -d
	@echo ""
	@echo "Stack starting. Wait ~90s, then:"
	@echo "  Wazuh    https://localhost:443       admin / SecretPassword"
	@echo "  TheHive  http://localhost:9000       admin@thehive.local / secret"
	@echo "  Grafana  http://localhost:3000       admin / admin"
	@echo "  DVWA     http://localhost:8080       admin / password"

down:
	docker compose down

clean:
	docker compose down -v
	rm -f attack_timeline.json

status:
	@docker compose ps

logs:
	docker compose logs -f wazuh.manager

rules:
	python sigma_to_wazuh.py
	docker compose restart wazuh.manager

test:
	pytest test_detections.py -v

attack:
	python attack_chain.py --target http://localhost:8080

hunt:
	jupyter notebook notebooks/threat_hunting.ipynb
