# ---------------------------------------------------------------
# Win10-backdoor-analysis
# ONLY for an isolated lab (VM, host-only network). 'compile'
# builds a real backdoor. 'yara', 'check' and 'sigma' are
# analysis only.
# ---------------------------------------------------------------

CC_WIN   = i686-w64-mingw32-gcc
CC_HOST  = gcc

SRC      = Win10_backdoor
SAMPLES  = samples
RESULTS  = results
RULES_Y  = rules/yara
RULES_S  = rules/sigma

# Python venv holding sigma-cli and its plugins
VENV     = myvenv
SIGMA    = $(VENV)/bin/sigma
PIP      = $(VENV)/bin/pip

# Backend and pipeline for conversion (override from the terminal):
#   make sigma BACKEND=elasticsearch
BACKEND  = splunk
PIPELINE = sysmon

.PHONY: all help compile yara venv check sigma hashes clean clean-venv clean-all

all: compile yara sigma

help:
	@echo "make venv       - create the venv and install the sigma tooling"
	@echo "make compile    - build the backdoor (lab ONLY)"
	@echo "make yara       - scan samples/ with the YARA rules"
	@echo "make check      - validate the Sigma rule syntax"
	@echo "make sigma      - convert the Sigma rules into SIEM queries"
	@echo "make clean      - delete the binaries"
	@echo "make clean-venv - delete the venv"
	@echo "make clean-all  - clean + clean-venv + results"

# ---------- Python environment ----------

venv: $(SIGMA)

$(SIGMA):
	python3 -m venv $(VENV)
	$(PIP) install -U pip
	$(PIP) install -U sigma-cli pysigma-pipeline-sysmon pysigma-backend-splunk pysigma-backend-elasticsearch

# ---------- Build ----------

compile:
	mkdir -p $(SAMPLES)
	$(CC_WIN) -o $(SAMPLES)/malware.exe $(SRC)/backdoor.c -lwininet -lwsock32
	$(CC_HOST) -o $(SAMPLES)/server $(SRC)/server.c
	$(MAKE) hashes

hashes:
	sha256sum $(SAMPLES)/malware.exe $(SAMPLES)/server | tee $(SAMPLES)/hashes.txt

# ---------- Detection ----------

yara:
	mkdir -p $(RESULTS)
	yara -r -s $(RULES_Y)/*.yar $(SAMPLES)/ | tee $(RESULTS)/yara_hits.txt

check: $(SIGMA)
	$(SIGMA) check $(RULES_S)/

sigma: check
	mkdir -p $(RESULTS)
	$(SIGMA) convert -t $(BACKEND) -p $(PIPELINE) $(RULES_S)/ > $(RESULTS)/$(BACKEND)_queries.txt
	@echo "Queries saved to $(RESULTS)/$(BACKEND)_queries.txt"

# ---------- Cleanup ----------

clean:
	rm -f $(SAMPLES)/malware.exe $(SAMPLES)/server $(SAMPLES)/hashes.txt

clean-venv:
	rm -rf $(VENV)

clean-all: clean clean-venv
	rm -rf $(RESULTS)
