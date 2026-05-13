"""Regression graph — re-export of the builder defined in campaign_graph.

Kept as a separate module for the import surface CLAUDE.md §1 prescribes.
"""

from agentforge.graph.campaign_graph import build_regression_graph

__all__ = ["build_regression_graph"]
