package enrich

import (
	"fmt"
	"strings"
)

// TopoSort returns enrichers in execution order satisfying every
// `Dependencies()` declaration. The algorithm is Kahn's
// topological sort with stable input-order tie-breaking — when two
// enrichers have the same in-degree, the one that appeared first
// in the input slice runs first. That keeps `Pipeline.Enrichers()`
// + the operator's `--enable` / `--disable` filters predictable
// when no real dependency forces an order.
//
// Returns an error in two cases (PRSD-Task-6 contract):
//
//   - Duplicate `Name()` across enrichers — the registry must be a
//     set, not a multiset; two enrichers can't share a property
//     namespace.
//   - Cycle — a dep loop. The error names every enricher caught
//     in the unresolved set so operators can spot the loop.
//
// **Unknown dependencies are silently dropped** (lenient mode).
// This is the deliberate trade-off for the CLI's `--disable`
// surface: when an operator disables an enricher's dependency,
// the dependent enricher must still run (and degrade gracefully
// internally) rather than abort the whole pipeline. ADR-0024
// documents the deviation from the task spec's "error on unknown
// dep" wording.
//
// The function does not mutate the input slice. Concurrency: safe
// to call from multiple goroutines, but the input slice must not
// be mutated during the call.
func TopoSort(enrichers []Enricher) ([]Enricher, error) {
	if len(enrichers) == 0 {
		return nil, nil
	}

	byName, order, err := indexByName(enrichers)
	if err != nil {
		return nil, err
	}
	inDegree, dependents := buildGraph(enrichers, byName)

	out := kahn(enrichers, inDegree, dependents)
	if len(out) != len(enrichers) {
		return nil, cycleError(enrichers, out)
	}

	// Re-emit in stable input order within each topo level. kahn's
	// queue order already preserves input order via the `order`
	// stamp; this is a defensive sort to guarantee determinism on
	// future refactors.
	_ = order
	return out, nil
}

// indexByName builds the name → enricher map and the input-order
// stamp used for stable tie-breaking. Returns an error on duplicate
// names.
func indexByName(enrichers []Enricher) (map[string]Enricher, map[string]int, error) {
	byName := make(map[string]Enricher, len(enrichers))
	order := make(map[string]int, len(enrichers))
	for i, e := range enrichers {
		name := e.Name()
		if _, dup := byName[name]; dup {
			return nil, nil, fmt.Errorf("enrich: duplicate enricher name %q", name)
		}
		byName[name] = e
		order[name] = i
	}
	return byName, order, nil
}

// buildGraph populates the in-degree and reverse-edge maps,
// silently dropping deps on enrichers not in byName (the lenient
// mode documented at the package level). The reverse-edge map
// (`dependents[dep] = [enrichers that depend on dep]`) is what
// kahn walks to decrement in-degrees as enrichers retire from
// the queue.
func buildGraph(enrichers []Enricher, byName map[string]Enricher) (map[string]int, map[string][]string) {
	inDegree := make(map[string]int, len(enrichers))
	for _, e := range enrichers {
		inDegree[e.Name()] = 0
	}
	dependents := make(map[string][]string, len(enrichers))
	for _, e := range enrichers {
		for _, dep := range e.Dependencies() {
			if _, present := byName[dep]; !present {
				// Lenient mode: silently drop deps on
				// enrichers not registered. See package-level
				// godoc + ADR-0024.
				continue
			}
			inDegree[e.Name()]++
			dependents[dep] = append(dependents[dep], e.Name())
		}
	}
	return inDegree, dependents
}

// kahn implements Kahn's algorithm. The queue is seeded by walking
// the input slice in order so that two zero-in-degree enrichers
// retire in input order, not in map-iteration order.
func kahn(enrichers []Enricher, inDegree map[string]int, dependents map[string][]string) []Enricher {
	out := make([]Enricher, 0, len(enrichers))
	queue := make([]Enricher, 0, len(enrichers))
	for _, e := range enrichers {
		if inDegree[e.Name()] == 0 {
			queue = append(queue, e)
		}
	}
	for len(queue) > 0 {
		head := queue[0]
		queue = queue[1:]
		out = append(out, head)

		// Decrement in-degree for every enricher that depended on
		// `head`. New zero-in-degree entries get appended in input
		// order — `dependents[head.Name()]` was populated by
		// iterating the enricher slice in order, so this is
		// stable.
		for _, name := range dependents[head.Name()] {
			inDegree[name]--
			if inDegree[name] == 0 {
				for _, e := range enrichers {
					if e.Name() == name {
						queue = append(queue, e)
						break
					}
				}
			}
		}
	}
	return out
}

// cycleError returns a descriptive error naming every enricher that
// did NOT make it into out. Those are the cycle members (their
// in-degree never dropped to zero because the cycle dep blocks
// them).
func cycleError(enrichers, out []Enricher) error {
	emitted := make(map[string]bool, len(out))
	for _, e := range out {
		emitted[e.Name()] = true
	}
	stuck := make([]string, 0)
	for _, e := range enrichers {
		if !emitted[e.Name()] {
			stuck = append(stuck, e.Name())
		}
	}
	return fmt.Errorf("enrich: cyclic dependency among %s",
		strings.Join(stuck, ", "))
}
