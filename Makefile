.PHONY: dev check demo binwalk

dev:
	python3 scripts/task.py dev

check:
	python3 scripts/task.py check

demo:
	python3 scripts/task.py demo

binwalk:
	python3 scripts/task.py binwalk
