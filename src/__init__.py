"""
OWASP Agentic Security Dataset
==============================

Machine-readable security intelligence for agentic AI systems.

This package provides structured data from the OWASP Top 10 for Agentic
Applications 2026, enabling security automation, threat modeling, and
integration with security tools.

Quick Start
-----------

    >>> from owasp_agentic_security import load_dataset, get_entry, get_threats_for_component
    >>> 
    >>> # Load the full dataset
    >>> data = load_dataset()
    >>> 
    >>> # Get a specific entry
    >>> asi01 = get_entry("ASI01")
    >>> print(asi01["title"])
    'Agent Goal Hijack'
    >>> 
    >>> # Find threats for a component type
    >>> threats = get_threats_for_component("llm_agent", data)

Data Generation
---------------

    >>> from owasp_agentic_security import generate_all_formats
    >>> 
    >>> # Generate JSON and YAML files
    >>> generate_all_formats(output_dir="./output")

Available Entries
-----------------

- ASI01: Agent Goal Hijack
- ASI02: Tool Misuse & Exploitation
- ASI03: Identity & Privilege Abuse
- ASI04: Agentic Supply Chain Vulnerabilities
- ASI05: Unexpected Code Execution (RCE)
- ASI06: Memory & Context Poisoning
- ASI07: Insecure Inter-Agent Communication
- ASI08: Cascading Failures
- ASI09: Human-Agent Trust Exploitation
- ASI10: Rogue Agents

License
-------
CC BY-SA 4.0 - Creative Commons Attribution-ShareAlike 4.0 International

Source
------
OWASP GenAI Security Project - Agentic Security Initiative
https://genai.owasp.org
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Package metadata
__version__ = "1.0.0"
__author__ = "OWASP GenAI Security Project"
__license__ = "CC-BY-SA-4.0"
__url__ = "https://github.com/YOUR_USERNAME/owasp-agentic-security-dataset"

# Version tuple for programmatic comparison
VERSION = tuple(map(int, __version__.split(".")))

# All public exports
__all__ = [
    # Metadata
    "__version__",
    "__author__",
    "__license__",
    "__url__",
    "VERSION",
    # Data loading
    "load_dataset",
    "load_entries",
    "load_mappings",
    # Entry access
    "get_entry",
    "get_entry_by_title",
    "list_entry_ids",
    "list_entry_titles",
    # Threat analysis
    "get_threats_for_component",
    "get_mitigations",
    "get_attack_scenarios",
    "get_related_llm_entries",
    # Framework mappings
    "get_asi_to_llm_mapping",
    "get_nhi_mappings",
    # Incident tracking
    "get_incidents",
    "get_incidents_by_asi",
    # Generation
    "generate_all_formats",
    "create_owasp_agentic_top10",
    # Constants
    "ASI_IDS",
    "COMPONENT_THREAT_MAP",
]

# Constants
ASI_IDS = [
    "ASI01", "ASI02", "ASI03", "ASI04", "ASI05",
    "ASI06", "ASI07", "ASI08", "ASI09", "ASI10"
]

COMPONENT_THREAT_MAP = {
    "llm_agent": ["ASI01", "ASI05", "ASI06", "ASI10"],
    "tool_integration": ["ASI02", "ASI04"],
    "multi_agent": ["ASI07", "ASI08"],
    "user_interface": ["ASI09"],
    "identity_system": ["ASI03"],
    "memory_store": ["ASI06"],
    "code_executor": ["ASI05"],
    "orchestrator": ["ASI01", "ASI08", "ASI10"],
    "external_api": ["ASI02", "ASI04"],
    "communication_layer": ["ASI07"],
    "supply_chain": ["ASI04"],
    "rag_system": ["ASI01", "ASI06"],
}

# Lazy-loaded dataset cache
_dataset_cache: Optional[Dict[str, Any]] = None


def _get_data_path() -> Path:
    """Get the path to the data directory."""
    return Path(__file__).parent.parent / "data"


def _get_parser_module():
    """Lazy import of the parser module."""
    from . import owasp_agentic_parser
    return owasp_agentic_parser


def load_dataset(
    filepath: Optional[Union[str, Path]] = None,
    use_cache: bool = True
) -> Dict[str, Any]:
    """
    Load the complete OWASP Agentic Top 10 dataset.
    
    Args:
        filepath: Optional path to JSON file. If None, uses default location
                  or generates data if file doesn't exist.
        use_cache: Whether to cache the loaded data (default: True)
    
    Returns:
        Complete dataset dictionary with entries, mappings, and metadata.
    
    Example:
        >>> data = load_dataset()
        >>> print(data["metadata"]["version"])
        '2026'
    """
    global _dataset_cache
    
    if use_cache and _dataset_cache is not None:
        return _dataset_cache
    
    if filepath is not None:
        path = Path(filepath)
    else:
        path = _get_data_path() / "owasp_agentic_top10_full.json"
    
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        # Generate data if file doesn't exist
        parser = _get_parser_module()
        data = parser.create_owasp_agentic_top10()
    
    if use_cache:
        _dataset_cache = data
    
    return data


def load_entries(filepath: Optional[Union[str, Path]] = None) -> List[Dict[str, Any]]:
    """
    Load only the ASI entries from the dataset.
    
    Args:
        filepath: Optional path to entries JSON file.
    
    Returns:
        List of ASI entry dictionaries.
    
    Example:
        >>> entries = load_entries()
        >>> print(len(entries))
        10
    """
    if filepath is not None:
        path = Path(filepath)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("entries", data)
    
    data = load_dataset()
    return data["entries"]


def load_mappings(filepath: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """
    Load framework mappings from the dataset.
    
    Args:
        filepath: Optional path to mappings JSON file.
    
    Returns:
        Dictionary with ASI-LLM and NHI mappings.
    """
    if filepath is not None:
        path = Path(filepath)
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    
    data = load_dataset()
    return {
        "asi_llm_mappings": data["mappings"],
        "nhi_mappings": data["nhi_mappings"]
    }


def get_entry(asi_id: str) -> Optional[Dict[str, Any]]:
    """
    Get a specific ASI entry by ID.
    
    Args:
        asi_id: Entry ID (e.g., "ASI01", "ASI10")
    
    Returns:
        Entry dictionary or None if not found.
    
    Example:
        >>> entry = get_entry("ASI01")
        >>> print(entry["title"])
        'Agent Goal Hijack'
    """
    asi_id = asi_id.upper()
    entries = load_entries()
    for entry in entries:
        if entry["id"] == asi_id:
            return entry
    return None


def get_entry_by_title(title: str) -> Optional[Dict[str, Any]]:
    """
    Get an ASI entry by title (case-insensitive partial match).
    
    Args:
        title: Full or partial title to search for.
    
    Returns:
        First matching entry or None.
    
    Example:
        >>> entry = get_entry_by_title("goal hijack")
        >>> print(entry["id"])
        'ASI01'
    """
    title_lower = title.lower()
    entries = load_entries()
    for entry in entries:
        if title_lower in entry["title"].lower():
            return entry
    return None


def list_entry_ids() -> List[str]:
    """
    Get list of all ASI entry IDs.
    
    Returns:
        List of IDs: ["ASI01", "ASI02", ..., "ASI10"]
    """
    return ASI_IDS.copy()


def list_entry_titles() -> Dict[str, str]:
    """
    Get mapping of ASI IDs to titles.
    
    Returns:
        Dictionary mapping IDs to titles.
    
    Example:
        >>> titles = list_entry_titles()
        >>> print(titles["ASI01"])
        'Agent Goal Hijack'
    """
    entries = load_entries()
    return {entry["id"]: entry["title"] for entry in entries}


def get_threats_for_component(
    component_type: str,
    data: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Get relevant ASI threats for an architecture component type.
    
    Args:
        component_type: Type of component. Valid types:
            - llm_agent, tool_integration, multi_agent, user_interface
            - identity_system, memory_store, code_executor, orchestrator
            - external_api, communication_layer, supply_chain, rag_system
        data: Optional preloaded dataset.
    
    Returns:
        List of relevant ASI entry dictionaries.
    
    Example:
        >>> threats = get_threats_for_component("llm_agent")
        >>> print([t["id"] for t in threats])
        ['ASI01', 'ASI05', 'ASI06', 'ASI10']
    """
    component_type = component_type.lower()
    
    if component_type not in COMPONENT_THREAT_MAP:
        valid_types = ", ".join(sorted(COMPONENT_THREAT_MAP.keys()))
        raise ValueError(
            f"Unknown component type: '{component_type}'. "
            f"Valid types: {valid_types}"
        )
    
    relevant_ids = COMPONENT_THREAT_MAP[component_type]
    
    if data is None:
        data = load_dataset()
    
    return [
        entry for entry in data["entries"]
        if entry["id"] in relevant_ids
    ]


def get_mitigations(asi_id: str) -> List[str]:
    """
    Get all mitigations for a specific ASI entry.
    
    Args:
        asi_id: Entry ID (e.g., "ASI01")
    
    Returns:
        List of mitigation strings.
    
    Raises:
        ValueError: If entry ID not found.
    """
    entry = get_entry(asi_id)
    if entry is None:
        raise ValueError(f"Entry not found: {asi_id}")
    return entry["mitigations"]


def get_attack_scenarios(asi_id: str) -> List[Dict[str, str]]:
    """
    Get all attack scenarios for a specific ASI entry.
    
    Args:
        asi_id: Entry ID (e.g., "ASI01")
    
    Returns:
        List of scenario dictionaries with 'name' and 'description'.
    
    Raises:
        ValueError: If entry ID not found.
    """
    entry = get_entry(asi_id)
    if entry is None:
        raise ValueError(f"Entry not found: {asi_id}")
    return entry["attack_scenarios"]


def get_related_llm_entries(asi_id: str) -> List[str]:
    """
    Get related OWASP LLM Top 10 entries for an ASI entry.
    
    Args:
        asi_id: Entry ID (e.g., "ASI01")
    
    Returns:
        List of related LLM Top 10 entry references.
    
    Example:
        >>> related = get_related_llm_entries("ASI01")
        >>> print(related)
        ['LLM01:2025 Prompt Injection', 'LLM06:2025 Excessive Agency']
    """
    entry = get_entry(asi_id)
    if entry is None:
        raise ValueError(f"Entry not found: {asi_id}")
    return entry["related_llm_entries"]


def get_asi_to_llm_mapping() -> Dict[str, List[str]]:
    """
    Get complete ASI to LLM Top 10 mapping.
    
    Returns:
        Dictionary mapping ASI IDs to lists of related LLM entries.
    
    Example:
        >>> mapping = get_asi_to_llm_mapping()
        >>> print(mapping["ASI01"])
        ['LLM01:2025 Prompt Injection', 'LLM06:2025 Excessive Agency']
    """
    entries = load_entries()
    return {
        entry["id"]: entry["related_llm_entries"]
        for entry in entries
    }


def get_nhi_mappings() -> List[Dict[str, Any]]:
    """
    Get Non-Human Identities (NHI) Top 10 mappings.
    
    Returns:
        List of NHI mapping dictionaries.
    """
    data = load_dataset()
    return data["nhi_mappings"]["mappings"]


def get_incidents() -> List[Dict[str, Any]]:
    """
    Get all tracked real-world security incidents.
    
    Returns:
        List of incident dictionaries with name, date, description,
        related_asi, and source.
    
    Example:
        >>> incidents = get_incidents()
        >>> print(incidents[0]["name"])
        'EchoLeak'
    """
    data = load_dataset()
    return data["exploits_tracker"]["incidents"]


def get_incidents_by_asi(asi_id: str) -> List[Dict[str, Any]]:
    """
    Get incidents related to a specific ASI entry.
    
    Args:
        asi_id: Entry ID (e.g., "ASI01")
    
    Returns:
        List of related incident dictionaries.
    """
    asi_id = asi_id.upper()
    incidents = get_incidents()
    return [
        incident for incident in incidents
        if asi_id in incident.get("related_asi", [])
    ]


def generate_all_formats(output_dir: Union[str, Path] = ".") -> Dict[str, Path]:
    """
    Generate all JSON and YAML output files.
    
    Args:
        output_dir: Directory to write output files.
    
    Returns:
        Dictionary mapping format names to output file paths.
    
    Example:
        >>> files = generate_all_formats("./output")
        >>> print(files["full_json"])
        PosixPath('output/owasp_agentic_top10_full.json')
    """
    import os
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Change to output directory and run parser
    original_dir = os.getcwd()
    os.chdir(output_path)
    
    try:
        parser = _get_parser_module()
        parser.main()
    finally:
        os.chdir(original_dir)
    
    return {
        "full_json": output_path / "owasp_agentic_top10_full.json",
        "full_yaml": output_path / "owasp_agentic_top10_full.yaml",
        "entries_json": output_path / "owasp_agentic_top10_entries.json",
        "entries_yaml": output_path / "owasp_agentic_top10_entries.yaml",
        "mappings_json": output_path / "owasp_agentic_top10_mappings.json",
        "mappings_yaml": output_path / "owasp_agentic_top10_mappings.yaml",
        "simplified_json": output_path / "owasp_agentic_top10_simplified.json",
        "simplified_yaml": output_path / "owasp_agentic_top10_simplified.yaml",
    }


def create_owasp_agentic_top10() -> Dict[str, Any]:
    """
    Create the complete OWASP Agentic Top 10 data structure.
    
    This is the main data generation function. Use this if you want
    to generate fresh data without loading from files.
    
    Returns:
        Complete dataset dictionary.
    """
    parser = _get_parser_module()
    return parser.create_owasp_agentic_top10()


def clear_cache() -> None:
    """Clear the cached dataset to force reload on next access."""
    global _dataset_cache
    _dataset_cache = None


# Module-level convenience: print summary when imported interactively
def _print_summary() -> None:
    """Print a brief summary of the package."""
    print(f"OWASP Agentic Security Dataset v{__version__}")
    print(f"License: {__license__}")
    print(f"Entries: {', '.join(ASI_IDS)}")
    print(f"Use load_dataset() to get started.")