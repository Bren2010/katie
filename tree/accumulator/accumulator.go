// Package accumulator implements a cryptographic accumulator capable of
// producing proofs of inclusion, exclusion, and subset.
package accumulator

// Collector queues up many new entries to an accumulator to be added later, in
// a bulk operation.
type Collector struct {
}
