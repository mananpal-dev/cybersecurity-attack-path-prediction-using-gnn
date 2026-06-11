"""
graph/connection.py
────────────────────
Neo4j graph database connection manager.

The Neo4j backend is OPTIONAL. The dashboard and all analysis
functions work fully without it using in-memory NetworkX graphs.

Neo4j is useful when you want to:
  • Persist network topology across sessions
  • Run Cypher queries against the attack graph
  • Integrate with existing security infrastructure

Usage:
    from graph.connection import get_driver, is_neo4j_available

    if is_neo4j_available():
        with get_driver().session() as session:
            session.run("MATCH (n) RETURN count(n)")
"""

import os
import sys
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Load .env if present (graceful — never crash without it)
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass  # python-dotenv not installed; rely on real env vars

# Connection parameters from environment (with safe defaults)
NEO4J_URI      = os.getenv("NEO4J_URI",      "bolt://localhost:7687")
NEO4J_USER     = os.getenv("NEO4J_USER",      "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD",  "password")

_driver = None
_neo4j_available: Optional[bool] = None


def is_neo4j_available() -> bool:
    """
    Check whether a Neo4j connection can be established.
    Result is cached after first call.
    """
    global _neo4j_available
    if _neo4j_available is not None:
        return _neo4j_available

    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        driver.verify_connectivity()
        driver.close()
        _neo4j_available = True
        logger.info("Neo4j connection verified: %s", NEO4J_URI)
    except Exception as e:
        _neo4j_available = False
        logger.debug("Neo4j not available (%s). Using in-memory backend.", e)

    return _neo4j_available


def get_driver():
    """
    Return a cached Neo4j driver instance.

    Raises:
        RuntimeError: if Neo4j is not available.
    """
    global _driver
    if _driver is None:
        if not is_neo4j_available():
            raise RuntimeError(
                "Neo4j is not available. "
                "Set NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD in .env "
                "or run without Neo4j (the dashboard works without it)."
            )
        from neo4j import GraphDatabase
        _driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    return _driver


def close_driver() -> None:
    """Close the cached driver connection."""
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None
