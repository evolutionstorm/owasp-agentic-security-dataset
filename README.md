# OWASP Agentic Security Dataset

[![License: CC BY-SA 4.0](https://img.shields.io/badge/License-CC%20BY--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-sa/4.0/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![OWASP](https://img.shields.io/badge/OWASP-Agentic%20Top%2010-orange.svg)](https://genai.owasp.org)

**Machine-readable security intelligence for agentic AI systems.**

This repository provides structured JSON and YAML datasets derived from the [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org), enabling security automation, threat modeling, and integration with security tools.

---

##  Purpose

As AI agents become prevalent in enterprise systems, security teams need machine-readable threat intelligence to:

- **Automate threat modeling** for agentic architectures
- **Generate security scanning rules** based on known vulnerabilities
- **Map compliance requirements** across security frameworks
- **Build security training datasets** for AI-powered tools
- **Track real-world incidents** affecting agentic systems

##  What's Included

### Core Datasets

| File | Description |
|------|-------------|
| `data/owasp_agentic_top10_full.json` | Complete dataset with all entries, mappings, and incidents |
| `data/owasp_agentic_top10_full.yaml` | Same data in YAML format |
| `data/owasp_agentic_top10_entries.json` | ASI01-ASI10 entries only (lightweight) |
| `data/owasp_agentic_top10_mappings.json` | Framework cross-mappings only |
| `data/owasp_agentic_top10_simplified.json` | Quick reference (IDs, titles, summaries) |

### Data Structure

Each ASI entry includes:

```json
{
  "id": "ASI01",
  "title": "Agent Goal Hijack",
  "description": "...",
  "related_threats": ["T06 Goal Manipulation", "T07 Misaligned & Deceptive Behaviors"],
  "related_llm_entries": ["LLM01:2025 Prompt Injection", "LLM06:2025 Excessive Agency"],
  "aivss_core_risk": "Agent Goal & Instruction Manipulation",
  "common_examples": ["..."],
  "attack_scenarios": [{"name": "...", "description": "..."}],
  "mitigations": ["..."],
  "references": [{"title": "...", "url": "..."}]
}
```

### Framework Mappings

Cross-references between:
- **OWASP Agentic Top 10 (ASI)** ↔ **OWASP LLM Top 10 2025**
- **OWASP Agentic Threats & Mitigations v1.1**
- **OWASP AIVSS** (AI Vulnerability Scoring System)
- **NHI Top 10** (Non-Human Identities)

### Real-World Exploits Tracker

Documented incidents including:
- EchoLeak (Microsoft 365 Copilot zero-click exfiltration)
- ChatGPT Operator web content injection
- Salesforce Agentforce ForcedLeak
- Malicious MCP server attacks
- Amazon Q prompt poisoning

##  Quick Start

### Option 1: Use Pre-Generated Data

Download the JSON/YAML files directly from the `data/` directory.

### Option 2: Generate Fresh Data

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/owasp-agentic-security-dataset.git
cd owasp-agentic-security-dataset

# Install dependencies
pip install -r requirements.txt

# Generate datasets
python src/owasp_agentic_parser.py

# Output files will be in the current directory
```

##  Statistics

| Metric | Count |
|--------|-------|
| ASI Entries | 10 |
| Total Mitigations | 80+ |
| Attack Scenarios | 70+ |
| Common Examples | 60+ |
| Tracked Incidents | 11+ |
| NHI Mappings | 10 |

##  Integration Examples

### Python - Load and Query

```python
import json

with open('data/owasp_agentic_top10_full.json') as f:
    data = json.load(f)

# Find all mitigations for prompt injection related threats
for entry in data['entries']:
    if 'Prompt Injection' in str(entry['related_llm_entries']):
        print(f"{entry['id']}: {entry['title']}")
        for m in entry['mitigations']:
            print(f"  - {m}")
```

### Security Tool Integration

```python
# Generate detection rules from attack scenarios
def generate_detection_rules(data):
    rules = []
    for entry in data['entries']:
        for scenario in entry['attack_scenarios']:
            rules.append({
                'rule_id': f"{entry['id']}_{scenario['name'][:20].replace(' ', '_')}",
                'severity': 'HIGH',
                'description': scenario['description'],
                'framework_ref': entry['id'],
                'mitigations': entry['mitigations']
            })
    return rules
```

### Threat Modeling Automation

```python
# Map ASI entries to your architecture components
def analyze_component(component_type, data):
    relevant_threats = []
    
    threat_mapping = {
        'llm_agent': ['ASI01', 'ASI05', 'ASI06', 'ASI10'],
        'tool_integration': ['ASI02', 'ASI04'],
        'multi_agent': ['ASI07', 'ASI08'],
        'user_interface': ['ASI09'],
        'identity_system': ['ASI03']
    }
    
    for entry in data['entries']:
        if entry['id'] in threat_mapping.get(component_type, []):
            relevant_threats.append(entry)
    
    return relevant_threats
```

## 📁 Repository Structure

```
owasp-agentic-security-dataset/
├── README.md
├── LICENSE
├── CHANGELOG.md
├── CONTRIBUTING.md
├── requirements.txt
├── pyproject.toml
├── .gitignore
├── src/
│   └── owasp_agentic_parser.py    # Parser script
├── data/
│   ├── owasp_agentic_top10_full.json
│   ├── owasp_agentic_top10_full.yaml
│   ├── owasp_agentic_top10_entries.json
│   ├── owasp_agentic_top10_entries.yaml
│   ├── owasp_agentic_top10_mappings.json
│   ├── owasp_agentic_top10_mappings.yaml
│   ├── owasp_agentic_top10_simplified.json
│   └── owasp_agentic_top10_simplified.yaml
├── examples/
│   ├── threat_modeling.py
│   ├── rule_generation.py
│   └── compliance_mapping.py
├── tests/
│   └── test_parser.py
└── docs/
    ├── SCHEMA.md
    └── MAPPINGS.md
```

## 🔗 Related Resources

- [OWASP GenAI Security Project](https://genai.owasp.org)
- [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Agentic AI Threats & Mitigations](https://genai.owasp.org)
- [OWASP AI Vulnerability Scoring System (AIVSS)](https://genai.owasp.org)
- [OWASP MCP Top 10](https://genai.owasp.org)

## 📜 License

This dataset is derived from OWASP materials and is licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).

**Attribution:** OWASP GenAI Security Project - Agentic Security Initiative

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

- Report issues with data accuracy
- Submit PRs for new framework mappings
- Add integration examples
- Improve documentation

## ⚠️ Disclaimer

This dataset is provided for security research and defensive purposes. The information is derived from publicly available OWASP materials. Always verify current threat intelligence and adapt mitigations to your specific environment.

---

**Built for the security community by security practitioners.**
