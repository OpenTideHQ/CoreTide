"""Property-based tests for TVM recursive chaining resolution.

**Validates: Requirements 5.5**

Property 8: TVM recursive chaining resolution
- For any TVM object in a chaining graph (including graphs with cycles, deep chains,
  and disconnected components), `_resolve_tvm_chains()` SHALL return all transitively
  reachable TVM UUIDs without duplicates and without infinite recursion.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import git

# Add project root to Python path
project_root = Path(git.Repo(".", search_parent_directories=True).working_dir)
sys.path.insert(0, str(project_root))

# Mock the heavy imports before importing from relations module
sys.modules['Engines.modules.tide'] = MagicMock()
sys.modules['Engines.modules.logs'] = MagicMock()

import pytest
from hypothesis import given, strategies as st, assume, settings, HealthCheck
from typing import Dict, List, Set, Tuple

# Import the actual function we're testing
from Engines.sharing.relations import _resolve_tvm_chains


# Strategy for generating valid UUIDs
uuid_strategy = st.uuids().map(str)


@st.composite
def simple_chaining_index_strategy(draw):
    """Generate a simple chaining index with no cycles.
    
    Returns a tuple of (chaining_index, start_uuid, expected_reachable_uuids).
    """
    # Generate a set of UUIDs for the graph
    num_nodes = draw(st.integers(min_value=1, max_value=10))
    node_uuids = [draw(uuid_strategy) for _ in range(num_nodes)]
    
    # Ensure uniqueness
    node_uuids = list(set(node_uuids))
    if len(node_uuids) < 1:
        node_uuids = [draw(uuid_strategy)]
    
    # Build a DAG by only allowing edges from earlier to later nodes
    chaining_index: Dict[str, Dict[str, List[str]]] = {}
    
    for i, uuid in enumerate(node_uuids):
        if i < len(node_uuids) - 1:
            # Add edges to some later nodes
            later_nodes = node_uuids[i + 1:]
            if later_nodes:
                num_edges = draw(st.integers(min_value=0, max_value=min(3, len(later_nodes))))
                if num_edges > 0:
                    targets = draw(st.lists(
                        st.sampled_from(later_nodes),
                        min_size=num_edges,
                        max_size=num_edges,
                        unique=True
                    ))
                    chaining_index[uuid] = {"relation": targets}
    
    # Start from the first node
    start_uuid = node_uuids[0]
    
    # Calculate expected reachable UUIDs
    expected = compute_reachable_uuids(start_uuid, chaining_index)
    
    return chaining_index, start_uuid, expected


@st.composite
def cyclic_chaining_index_strategy(draw):
    """Generate a chaining index with cycles.
    
    Returns a tuple of (chaining_index, start_uuid, expected_reachable_uuids).
    """
    # Generate a small set of UUIDs
    num_nodes = draw(st.integers(min_value=2, max_value=6))
    node_uuids = [draw(uuid_strategy) for _ in range(num_nodes)]
    
    # Ensure uniqueness
    node_uuids = list(set(node_uuids))
    if len(node_uuids) < 2:
        node_uuids = [draw(uuid_strategy), draw(uuid_strategy)]
    
    chaining_index: Dict[str, Dict[str, List[str]]] = {}
    
    # Build a graph with a guaranteed cycle
    for i, uuid in enumerate(node_uuids):
        # Create edges to random nodes (including possible back-edges)
        num_edges = draw(st.integers(min_value=0, max_value=min(3, len(node_uuids) - 1)))
        if num_edges > 0:
            # Allow any node as target except self
            possible_targets = [n for n in node_uuids if n != uuid]
            if possible_targets:
                targets = draw(st.lists(
                    st.sampled_from(possible_targets),
                    min_size=num_edges,
                    max_size=num_edges,
                    unique=True
                ))
                chaining_index[uuid] = {"relation": targets}
    
    # Ensure there's at least one cycle by adding an explicit back edge
    if len(node_uuids) >= 2:
        first = node_uuids[0]
        last = node_uuids[-1]
        # Add edge from last to first
        if last not in chaining_index:
            chaining_index[last] = {"relation": [first]}
        elif "relation" in chaining_index[last]:
            if first not in chaining_index[last]["relation"]:
                chaining_index[last]["relation"].append(first)
        else:
            chaining_index[last]["relation"] = [first]
    
    start_uuid = node_uuids[0]
    expected = compute_reachable_uuids(start_uuid, chaining_index)
    
    return chaining_index, start_uuid, expected


@st.composite
def deep_chain_strategy(draw):
    """Generate a deep linear chain.
    
    Returns a tuple of (chaining_index, start_uuid, expected_reachable_uuids).
    """
    # Generate a chain of 5-20 nodes
    depth = draw(st.integers(min_value=5, max_value=20))
    node_uuids = [draw(uuid_strategy) for _ in range(depth)]
    
    # Ensure uniqueness
    seen = set()
    unique_uuids = []
    for uuid in node_uuids:
        if uuid not in seen:
            seen.add(uuid)
            unique_uuids.append(uuid)
    node_uuids = unique_uuids
    
    if len(node_uuids) < 5:
        # Generate more unique UUIDs if needed
        while len(node_uuids) < 5:
            new_uuid = draw(uuid_strategy)
            if new_uuid not in seen:
                seen.add(new_uuid)
                node_uuids.append(new_uuid)
    
    # Build a linear chain
    chaining_index: Dict[str, Dict[str, List[str]]] = {}
    for i in range(len(node_uuids) - 1):
        chaining_index[node_uuids[i]] = {"relation": [node_uuids[i + 1]]}
    
    start_uuid = node_uuids[0]
    # All nodes except the start should be reachable
    expected = set(node_uuids[1:])
    
    return chaining_index, start_uuid, expected


@st.composite
def disconnected_components_strategy(draw):
    """Generate a graph with disconnected components.
    
    Returns a tuple of (chaining_index, start_uuid, expected_reachable_uuids).
    """
    # Generate two separate components
    component1_size = draw(st.integers(min_value=2, max_value=5))
    component2_size = draw(st.integers(min_value=2, max_value=5))
    
    component1_uuids = [draw(uuid_strategy) for _ in range(component1_size)]
    component2_uuids = [draw(uuid_strategy) for _ in range(component2_size)]
    
    # Ensure uniqueness within and across components
    all_uuids = set(component1_uuids + component2_uuids)
    component1_uuids = list(all_uuids)[:component1_size]
    component2_uuids = list(all_uuids)[component1_size:component1_size + component2_size]
    
    # Ensure minimum sizes
    while len(component1_uuids) < 2:
        component1_uuids.append(draw(uuid_strategy))
    while len(component2_uuids) < 2:
        component2_uuids.append(draw(uuid_strategy))
    
    chaining_index: Dict[str, Dict[str, List[str]]] = {}
    
    # Build component 1 as a linear chain
    for i in range(len(component1_uuids) - 1):
        chaining_index[component1_uuids[i]] = {"relation": [component1_uuids[i + 1]]}
    
    # Build component 2 as a linear chain
    for i in range(len(component2_uuids) - 1):
        chaining_index[component2_uuids[i]] = {"relation": [component2_uuids[i + 1]]}
    
    # Start from first component
    start_uuid = component1_uuids[0]
    # Only first component should be reachable
    expected = set(component1_uuids[1:])
    
    return chaining_index, start_uuid, expected, component2_uuids


def compute_reachable_uuids(start_uuid: str, chaining_index: Dict) -> Set[str]:
    """Compute all reachable UUIDs from start_uuid using BFS/DFS.
    
    This is the reference implementation to compare against.
    """
    visited: Set[str] = set()
    reachable: Set[str] = set()
    stack = [start_uuid]
    
    while stack:
        current = stack.pop()
        if current in visited:
            continue
        visited.add(current)
        
        if current in chaining_index:
            for relation_name, targets in chaining_index[current].items():
                for target in targets:
                    if target not in visited:
                        reachable.add(target)
                        stack.append(target)
    
    return reachable


class TestProperty8TVMRecursiveChaining:
    """Property tests for TVM recursive chaining resolution (Property 8).
    
    **Validates: Requirements 5.5**
    
    Property 8: TVM recursive chaining resolution
    - For any TVM object in a chaining graph (including graphs with cycles, deep chains,
      and disconnected components), _resolve_tvm_chains() SHALL return all transitively
      reachable TVM UUIDs without duplicates and without infinite recursion.
    """

    @given(data=simple_chaining_index_strategy())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_dag_returns_all_reachable_uuids(self, data: Tuple):
        """Test that DAG traversal returns all transitively reachable UUIDs.
        
        **Validates: Requirements 5.5**
        
        For any directed acyclic graph, _resolve_tvm_chains() should return
        all UUIDs that are reachable from the start node via any path.
        """
        chaining_index, start_uuid, expected = data
        
        result = _resolve_tvm_chains(start_uuid, chaining_index)
        
        # Convert result to set for comparison
        result_set = set(result)
        
        # Should contain all expected UUIDs
        assert result_set == expected, (
            f"Expected reachable UUIDs {expected}, but got {result_set}"
        )

    @given(data=cyclic_chaining_index_strategy())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_cyclic_graph_no_infinite_recursion(self, data: Tuple):
        """Test that cyclic graphs do not cause infinite recursion.
        
        **Validates: Requirements 5.5**
        
        For any graph containing cycles, _resolve_tvm_chains() should
        terminate and return results without infinite recursion.
        """
        chaining_index, start_uuid, expected = data
        
        # This should not hang or raise RecursionError
        result = _resolve_tvm_chains(start_uuid, chaining_index)
        
        # Convert result to set for comparison
        result_set = set(result)
        
        # Should contain all expected UUIDs
        assert result_set == expected

    @given(data=cyclic_chaining_index_strategy())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_cyclic_graph_no_duplicates(self, data: Tuple):
        """Test that cyclic graphs do not produce duplicate UUIDs in results.
        
        **Validates: Requirements 5.5**
        
        For any graph containing cycles, _resolve_tvm_chains() should
        return each reachable UUID exactly once.
        """
        chaining_index, start_uuid, _ = data
        
        result = _resolve_tvm_chains(start_uuid, chaining_index)
        
        # Check for duplicates
        assert len(result) == len(set(result)), (
            f"Result contains duplicates: {result}"
        )

    @given(data=deep_chain_strategy())
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_deep_chains_traverse_completely(self, data: Tuple):
        """Test that deep chains are traversed completely.
        
        **Validates: Requirements 5.5**
        
        For a linear chain of any depth, _resolve_tvm_chains() should
        return all nodes in the chain except the start node.
        """
        chaining_index, start_uuid, expected = data
        
        result = _resolve_tvm_chains(start_uuid, chaining_index)
        
        # Convert result to set for comparison
        result_set = set(result)
        
        # Should contain all nodes except start
        assert result_set == expected, (
            f"Expected {len(expected)} nodes, got {len(result_set)}"
        )

    @given(data=disconnected_components_strategy())
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_disconnected_components_only_reachable(self, data: Tuple):
        """Test that only reachable components are included.
        
        **Validates: Requirements 5.5**
        
        For a graph with disconnected components, _resolve_tvm_chains() should
        only return UUIDs from the component reachable from the start node.
        """
        chaining_index, start_uuid, expected, unreachable_component = data
        
        result = _resolve_tvm_chains(start_uuid, chaining_index)
        result_set = set(result)
        
        # Should contain only expected UUIDs (from reachable component)
        assert result_set == expected
        
        # Should not contain any UUIDs from unreachable component
        for uuid in unreachable_component:
            assert uuid not in result_set, (
                f"Found unreachable UUID {uuid} in results"
            )

    @given(uuid=uuid_strategy)
    def test_empty_chaining_index_returns_empty_list(self, uuid: str):
        """Test that an empty chaining index returns an empty list.
        
        **Validates: Requirements 5.5**
        
        When the chaining index is empty, there are no relations to traverse.
        """
        result = _resolve_tvm_chains(uuid, {})
        
        assert result == []

    @given(uuid=uuid_strategy)
    def test_uuid_not_in_index_returns_empty_list(self, uuid: str):
        """Test that a UUID not in the index returns an empty list.
        
        **Validates: Requirements 5.5**
        
        When the start UUID has no entry in the chaining index, there are
        no direct relations to follow.
        """
        chaining_index = {
            "other-uuid-1": {"relation": ["other-uuid-2"]},
            "other-uuid-2": {"relation": ["other-uuid-3"]},
        }
        
        # Ensure our UUID is not in the index
        assume(uuid not in chaining_index)
        
        result = _resolve_tvm_chains(uuid, chaining_index)
        
        assert result == []

    def test_self_referencing_node(self):
        """Test that a node referencing itself is handled correctly.
        
        **Validates: Requirements 5.5**
        
        A node that references itself should not cause infinite recursion
        and should not include itself in the result.
        """
        uuid = "self-ref-uuid"
        chaining_index = {
            uuid: {"relation": [uuid]}  # Self-reference
        }
        
        result = _resolve_tvm_chains(uuid, chaining_index)
        
        # The result should be empty because the only relation is to itself,
        # and the start node is not included in results
        assert result == []

    def test_self_referencing_node_with_other_relations(self):
        """Test a node with self-reference and other relations.
        
        **Validates: Requirements 5.5**
        """
        uuid_a = "uuid-a"
        uuid_b = "uuid-b"
        chaining_index = {
            uuid_a: {"relation": [uuid_a, uuid_b]},  # Self-reference + other
            uuid_b: {"relation": [uuid_a]},  # Back to A
        }
        
        result = _resolve_tvm_chains(uuid_a, chaining_index)
        
        # Should only include uuid_b (not uuid_a since it's the start node)
        assert set(result) == {uuid_b}

    def test_multiple_relation_types(self):
        """Test that all relation types are traversed.
        
        **Validates: Requirements 5.5**
        
        The chaining index may have multiple relation types (succeeds, precedes, etc.).
        All should be traversed.
        """
        uuid_a = "uuid-a"
        uuid_b = "uuid-b"
        uuid_c = "uuid-c"
        uuid_d = "uuid-d"
        
        chaining_index = {
            uuid_a: {
                "succeeds": [uuid_b],
                "precedes": [uuid_c],
            },
            uuid_b: {
                "related_to": [uuid_d],
            },
        }
        
        result = _resolve_tvm_chains(uuid_a, chaining_index)
        
        # Should include all reachable UUIDs across all relation types
        assert set(result) == {uuid_b, uuid_c, uuid_d}

    @given(
        uuid_a=uuid_strategy,
        uuid_b=uuid_strategy,
        uuid_c=uuid_strategy,
    )
    def test_triangular_cycle(self, uuid_a: str, uuid_b: str, uuid_c: str):
        """Test a simple triangular cycle (A → B → C → A).
        
        **Validates: Requirements 5.5**
        """
        # Ensure all UUIDs are unique
        assume(len({uuid_a, uuid_b, uuid_c}) == 3)
        
        chaining_index = {
            uuid_a: {"relation": [uuid_b]},
            uuid_b: {"relation": [uuid_c]},
            uuid_c: {"relation": [uuid_a]},
        }
        
        result = _resolve_tvm_chains(uuid_a, chaining_index)
        
        # Should return B and C (all reachable from A except A itself)
        assert set(result) == {uuid_b, uuid_c}
        # No duplicates
        assert len(result) == 2

    def test_diamond_pattern(self):
        """Test a diamond pattern (A → B,C; B → D; C → D).
        
        **Validates: Requirements 5.5**
        
        D should appear only once despite being reachable via two paths.
        """
        uuid_a = "uuid-a"
        uuid_b = "uuid-b"
        uuid_c = "uuid-c"
        uuid_d = "uuid-d"
        
        chaining_index = {
            uuid_a: {"relation": [uuid_b, uuid_c]},
            uuid_b: {"relation": [uuid_d]},
            uuid_c: {"relation": [uuid_d]},
        }
        
        result = _resolve_tvm_chains(uuid_a, chaining_index)
        
        # Should return B, C, D without duplicates
        assert set(result) == {uuid_b, uuid_c, uuid_d}
        assert len(result) == 3  # No duplicates

    @given(num_nodes=st.integers(min_value=2, max_value=15))
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_complete_graph(self, num_nodes: int):
        """Test a complete graph where every node is connected to every other node.
        
        **Validates: Requirements 5.5**
        
        Even with maximum connectivity, should terminate without duplicates.
        """
        # Generate unique UUIDs
        node_uuids = [f"node-{i}" for i in range(num_nodes)]
        
        # Build complete graph
        chaining_index = {}
        for uuid in node_uuids:
            others = [n for n in node_uuids if n != uuid]
            chaining_index[uuid] = {"relation": others}
        
        start_uuid = node_uuids[0]
        result = _resolve_tvm_chains(start_uuid, chaining_index)
        
        # Should return all nodes except start
        expected = set(node_uuids) - {start_uuid}
        assert set(result) == expected
        assert len(result) == len(expected)  # No duplicates

    def test_result_is_always_list(self):
        """Test that result is always a list, not other iterables.
        
        **Validates: Requirements 5.5**
        """
        chaining_index = {
            "a": {"relation": ["b", "c"]},
        }
        
        result = _resolve_tvm_chains("a", chaining_index)
        
        assert isinstance(result, list)

    def test_result_elements_are_strings(self):
        """Test that result elements are strings.
        
        **Validates: Requirements 5.5**
        """
        chaining_index = {
            "a": {"relation": ["b", "c"]},
        }
        
        result = _resolve_tvm_chains("a", chaining_index)
        
        for item in result:
            assert isinstance(item, str)


class TestEdgeCasesProperty8:
    """Edge case tests for TVM recursive chaining resolution.
    
    **Validates: Requirements 5.5**
    """

    def test_empty_relation_list(self):
        """Test a node with empty relation list."""
        chaining_index = {
            "uuid-a": {"relation": []},
        }
        
        result = _resolve_tvm_chains("uuid-a", chaining_index)
        
        assert result == []

    def test_empty_relations_dict(self):
        """Test a node with empty relations dictionary."""
        chaining_index = {
            "uuid-a": {},
        }
        
        result = _resolve_tvm_chains("uuid-a", chaining_index)
        
        assert result == []

    def test_nested_relation_types(self):
        """Test traversal across multiple different relation types."""
        chaining_index = {
            "a": {"type1": ["b"]},
            "b": {"type2": ["c"]},
            "c": {"type3": ["d"]},
        }
        
        result = _resolve_tvm_chains("a", chaining_index)
        
        assert set(result) == {"b", "c", "d"}

    def test_mixed_existing_nonexisting_targets(self):
        """Test when some targets have entries in index and some don't."""
        chaining_index = {
            "a": {"relation": ["b", "c"]},  # b has entry, c doesn't
            "b": {"relation": ["d"]},
        }
        
        result = _resolve_tvm_chains("a", chaining_index)
        
        # Should still include c even though it has no entry
        assert set(result) == {"b", "c", "d"}

    def test_visited_set_isolation(self):
        """Test that the visited set doesn't leak between calls."""
        chaining_index = {
            "a": {"relation": ["b"]},
            "b": {"relation": ["c"]},
        }
        
        # First call
        result1 = _resolve_tvm_chains("a", chaining_index)
        
        # Second call should produce same result
        result2 = _resolve_tvm_chains("a", chaining_index)
        
        assert set(result1) == set(result2) == {"b", "c"}

    @given(uuid=uuid_strategy)
    def test_consistent_results_across_calls(self, uuid: str):
        """Test that multiple calls with same input produce same output.
        
        **Validates: Requirements 5.5**
        """
        chaining_index = {
            uuid: {"relation": ["target-1", "target-2"]},
            "target-1": {"relation": ["target-3"]},
        }
        
        results = [_resolve_tvm_chains(uuid, chaining_index) for _ in range(5)]
        
        # All results should be equal (order may vary, so compare sets)
        first_set = set(results[0])
        for result in results[1:]:
            assert set(result) == first_set

