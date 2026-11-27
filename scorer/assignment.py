"""Deterministic maximum-weight matching of a sparse bipartite graph."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass


@dataclass
class _Edge:
    target: int
    reverse: int
    cost: int
    available: bool = True


def maximum_weight_assignment(
    candidates: list[tuple[int, int, int]],
) -> dict[int, int]:
    """Return left-to-right matches using positive weights and optional matches.

    Visit vertices and arcs in canonical order, keeping the first predecessor
    on equal costs. Each augmentation finds the best change, including swaps
    along reverse arcs, until another match would reduce the total weight.
    """
    if not candidates:
        return {}

    left = {key: node for node, key in enumerate(sorted({a for a, _, _ in candidates}), 1)}
    right = {
        key: node
        for node, key in enumerate(sorted({b for _, b, _ in candidates}), len(left) + 1)
    }
    source = 0
    sink = len(left) + len(right) + 1
    graph: list[list[_Edge]] = [[] for _ in range(sink + 1)]

    def connect(start: int, end: int, cost: int) -> _Edge:
        forward = _Edge(end, len(graph[end]), cost)
        reverse = _Edge(start, len(graph[start]), -cost, available=False)
        graph[start].append(forward)
        graph[end].append(reverse)
        return forward

    for node in left.values():
        connect(source, node, 0)
    for node in right.values():
        connect(node, sink, 0)
    arcs = {
        (a, b): connect(left[a], right[b], -weight)
        for a, b, weight in sorted(candidates)
    }

    while True:
        distance = {source: 0}
        predecessor: dict[int, tuple[int, _Edge]] = {}
        pending = deque([source])
        queued = {source}

        while pending:
            node = pending.popleft()
            queued.remove(node)
            if node == sink:
                continue
            for edge in graph[node]:
                if not edge.available or edge.target == source:
                    continue
                cost = distance[node] + edge.cost
                if edge.target in distance and cost >= distance[edge.target]:
                    continue
                distance[edge.target] = cost
                predecessor[edge.target] = node, edge
                if edge.target not in queued:
                    pending.append(edge.target)
                    queued.add(edge.target)

        if distance.get(sink, 0) >= 0:
            return {a: b for (a, b), edge in arcs.items() if not edge.available}

        node = sink
        while node != source:
            start, edge = predecessor[node]
            edge.available = False
            graph[edge.target][edge.reverse].available = True
            node = start
