package transparency

// // Verifier is a stateful verifier for the responses from a Transparency Log.
// type Verifier struct {
// 	config *structs.PublicConfig

// 	auditor    *structs.AuditorTreeHead
// 	log        *log.Verifier
// 	logEntries map[uint64]structs.LogEntry
// }

// func NewVerifier(config *structs.PublicConfig) *Verifier {
// 	return &Verifier{
// 		config: config,

// 		log: log.NewVerifier(config.Suite),
// 	}
// }

// // Last returns the previously observed tree size. This should be directly
// // inserted into the `last` field of requests.
// func (v *Verifier) Last() *uint64 { return v.log.Last() }

// func (v *Verifier) verifyTreeHead(fth *structs.FullTreeHead) (uint64, *uint64, *uint64, error) {
// 	last := v.Last()

// 	if fth.TreeHead == nil { // Tree head type is same.
// 		// Verify that the user advertised a previously observed tree size.
// 		if last == nil {
// 			return 0, nil, nil, errors.New("no tree head provided")
// 		}
// 		// Verify that the rightmost timestamp is still within the bounds set by
// 		// `max_ahead` and `max_behind`.
// 		entry, ok := v.logEntries[*last-1]
// 		if !ok {
// 			return 0, nil, nil, errors.New("expected log entry not found")
// 		}
// 		now := uint64(time.Now().UnixMilli())
// 		if now < entry.Timestamp && entry.Timestamp-now > v.config.MaxAhead {
// 			return 0, nil, nil, errors.New("rightmost timestamp is too far ahead of local clock")
// 		} else if now > entry.Timestamp && now-entry.Timestamp > v.config.MaxBehind {
// 			return 0, nil, nil, errors.New("rightmost timestamp is too far behind local clock")
// 		}
// 		return *last, nil, nil, nil
// 	}

// 	// If a previously observed tree size was advertised, verify that
// 	// `TreeHead.tree_size` is greater than it.
// 	if last != nil && fth.TreeHead.TreeSize <= *last {
// 		return 0, nil, nil, errors.New("received tree head has size less than or equal to what was advertised")
// 	}
// 	var nP *uint64
// 	if fth.AuditorTreeHead != nil {
// 		// If the user advertised a previously observed tree head, verify that
// 		// the `AuditorTreeHead.tree_size` field of the PREVIOUS tree head is
// 		// greater than or equal to `Configuration.auditor_start_pos`.
// 		if last != nil && v.auditor.TreeSize < v.config.AuditorStartPos {
// 			return 0, nil, nil, errors.New("auditor start position does not overlap with previous auditor")
// 		}
// 		// Verify that `AuditorTreeHead.tree_size` is less than or equal to
// 		// `TreeHead.tree_size`.
// 		if fth.AuditorTreeHead.TreeSize > fth.TreeHead.TreeSize {
// 			return 0, nil, nil, errors.New("auditor tree size greater than service operator tree size")
// 		}
// 		nP = &fth.AuditorTreeHead.TreeSize
// 	}

// 	return fth.TreeHead.TreeSize, nP, last, nil
// }

// // finish performs TreeHead and AuditorTreeHead verification steps that were
// // skipped in verifyTreeHead, and updates the verifier's state if they succeed.
// func (v *Verifier) finish(result *proofResult, fth *structs.FullTreeHead, provider *dataProvider) error {
// 	if fth.TreeHead == nil {
// 		return nil
// 	}

// 	// Verify service provider signature.
// 	root, err := log.Root(v.config.Suite, fth.TreeHead.TreeSize, result.frontier)
// 	if err != nil {
// 		return err
// 	}
// 	tbs, err := structs.Marshal(&structs.TreeHeadTBS{
// 		Config:   v.config,
// 		TreeSize: fth.TreeHead.TreeSize,
// 		Root:     root,
// 	})
// 	if err != nil {
// 		return err
// 	}
// 	ok := v.config.SignatureKey.Verify(tbs, fth.TreeHead.Signature)
// 	if !ok {
// 		return errors.New("service provider signature validation failed")
// 	}

// 	// Verify auditor tree head.
// 	if v.config.Mode == structs.ThirdPartyAuditing {
// 		// Verify auditor signature.
// 		root, err := log.Root(v.config.Suite, fth.AuditorTreeHead.TreeSize, result.additional)
// 		if err != nil {
// 			return err
// 		}
// 		tbs, err := structs.Marshal(&structs.AuditorTreeHeadTBS{
// 			Config:    v.config,
// 			Timestamp: fth.AuditorTreeHead.Timestamp,
// 			TreeSize:  fth.AuditorTreeHead.TreeSize,
// 			Root:      root,
// 		})
// 		if err != nil {
// 			return err
// 		}
// 		ok := v.config.AuditorPublicKey.Verify(tbs, fth.AuditorTreeHead.Signature)
// 		if !ok {
// 			return errors.New("auditor signature validation failed")
// 		}

// 		// Verify that the rightmost timestamp is greater than or equal to
// 		// `AuditorTreeHead.timestamp` and that the difference between the two
// 		// is less than or equal to `Configuration.max_auditor_lag`.
// 		ts, err := provider.GetTimestamp(fth.TreeHead.TreeSize - 1)
// 		if err != nil {
// 			return err
// 		} else if ts > fth.AuditorTreeHead.Timestamp {
// 			return errors.New("auditor timestamp is greater than rightmost timestamp")
// 		} else if fth.AuditorTreeHead.Timestamp-ts > v.config.MaxAuditorLag {
// 			return errors.New("auditor timestamp exceeds maximum lag")
// 		}
// 	}

// 	// Update verifier's retained state.
// 	v.auditor = fth.AuditorTreeHead
// 	v.log.Retain(fth.TreeHead.TreeSize, result.frontier)
// 	v.logEntries = result.logEntries
// 	return nil
// }

// func (v *Verifier) VerifySearch(req *structs.SearchRequest, res *structs.SearchResponse) error {
// 	if req.Last != v.Last() {
// 		return errors.New("request does not match verifier state")
// 	}
// 	n, nP, m, err := v.verifyTreeHead(&res.FullTreeHead)
// 	if err != nil {
// 		return err
// 	}

// 	handle := newReceivedProofHandler(v.config.Suite, res.Search)
// 	provider := newDataProvider(v.config.Suite, handle)

// 	if err := updateView(v.config, n, m, provider); err != nil {
// 		return err
// 	}
// 	if req.Version == nil {
// 		_, err = greatestVersionSearch(v.config, *res.Version, n, provider)
// 	} else {
// 		_, err = fixedVersionSearch(v.config, *req.Version, n, provider) // TODO: contact monitoring
// 	}
// 	if err != nil {
// 		return err
// 	}

// 	result, err := provider.Finish(n, nP, m)
// 	if err != nil {
// 		return err
// 	}
// 	if v.config.Mode == structs.ThirdPartyManagement {
// 		var ver uint32
// 		if req.Version == nil {
// 			ver = *res.Version
// 		} else {
// 			ver = *req.Version
// 		}
// 		tbs, err := structs.Marshal(&structs.UpdateTBS{
// 			Config: config,
// 			Label:   req.Label,
// 			Version: ver,
// 			Value:   res.Value.Value,
// 		})
// 		if err != nil {
// 			return err
// 		}
// 		ok := v.config.LeafPublicKey.Verify(tbs, res.Value.Signature)
// 		if !ok {
// 			return errors.New("leaf signature verification failed")
// 		}
// 	}
// 	return v.finish(result, &res.FullTreeHead, provider)
// }
