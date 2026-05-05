package prefix

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	mrand "math/rand"
	"testing"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/db/memory"
)

func randomBytes() [32]byte {
	out := [32]byte{}
	rand.Read(out[:])
	return out
}

func TestTree(t *testing.T) {
	cs := suites.KTSha256P256{}
	store := memory.NewPrefixStore()

	tree := NewTree(cs, store)
	roots := [][]byte{make([]byte, cs.HashSize())}
	data := make(map[[32]byte][32]byte)

	for ver := range uint64(10) {
		// Insert some random data into the tree.
		entries := make([]Entry, 0)
		for range 10 {
			vrfOutput, commitment := randomBytes(), randomBytes()

			entries = append(entries, Entry{vrfOutput[:], commitment[:]})
			data[vrfOutput] = commitment
		}
		root, proof, commitments, err := tree.Mutate(ver, entries, nil)
		if err != nil {
			t.Fatal(err)
		} else if len(commitments) > 0 {
			t.Fatal("unexpected number of commitments provided")
		}
		roots = append(roots, root)

		// Verify prior-version lookup proof.
		if err := Verify(cs, entries, proof, roots[ver]); err != nil {
			t.Fatal(err)
		}

		// Look up every VRF output and check that it matches what was
		// originally inserted.
		for vrfOutput, commitment := range data {
			res, err := tree.Search([]PrefixSearch{{ver + 1, [][]byte{vrfOutput[:]}}})
			if err != nil {
				t.Fatal(err)
			} else if len(res) != 1 {
				t.Fatal("unexpected number of versions returned")
			}
			verRes := res[0]
			if len(verRes.Proof.Results) != 1 || !verRes.Proof.Results[0].Inclusion() {
				t.Fatal("unexpected search result returned")
			} else if len(verRes.Commitments) != 1 {
				t.Fatal("unexpected number of commitments returned")
			} else if !bytes.Equal(verRes.Commitments[0], commitment[:]) {
				t.Fatal("unexpected commitment value returned")
			}
			err = Verify(cs, []Entry{{vrfOutput[:], commitment[:]}}, &verRes.Proof, root)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestUnableToInsertSameTwice(t *testing.T) {
	cs := suites.KTSha256P256{}
	store := memory.NewPrefixStore()

	tree := NewTree(cs, store)
	_, _, _, err := tree.Mutate(0, []Entry{{makeBytes(0), makeBytes(0)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = tree.Mutate(1, []Entry{{makeBytes(1), makeBytes(1)}, {makeBytes(1), makeBytes(1)}}, nil)
	if err == nil {
		t.Fatal("mutate did not return error when it should have")
	}
	_, _, _, err = tree.Mutate(1, []Entry{{makeBytes(0), makeBytes(0)}}, nil)
	if err == nil {
		t.Fatal("mutate did not return error when it should have")
	}
}

func TestUnableToAddAndRemoveSame(t *testing.T) {
	cs := suites.KTSha256P256{}
	store := memory.NewPrefixStore()

	tree := NewTree(cs, store)
	_, _, _, err := tree.Mutate(
		0,
		[]Entry{{makeBytes(0), makeBytes(0)}, {makeBytes(1), makeBytes(1)}},
		[][]byte{makeBytes(1)},
	)
	if err == nil {
		t.Fatal("mutate did not return error when it should have")
	}
}

func TestRemove(t *testing.T) {
	cs := suites.KTSha256P256{}
	store := memory.NewPrefixStore()

	tree := NewTree(cs, store)
	_, _, commitments, err := tree.Mutate(0, []Entry{
		{makeBytes(0), makeBytes(0)},
		{makeBytes(1), makeBytes(1)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	} else if len(commitments) > 0 {
		t.Fatal("unexpected number of commitments returned")
	}
	_, _, commitments, err = tree.Mutate(1, nil, [][]byte{makeBytes(0)})
	if err != nil {
		t.Fatal(err)
	} else if len(commitments) != 1 || !bytes.Equal(commitments[0], makeBytes(0)) {
		t.Fatal("unexpected commitment returned")
	}

	res, err := tree.Search([]PrefixSearch{{2, [][]byte{makeBytes(0), makeBytes(1)}}})
	if err != nil {
		t.Fatal(err)
	} else if len(res) != 1 {
		t.Fatal("unexpected number of results returned")
	}
	verRes := res[0]
	if len(verRes.Commitments) != 2 || len(verRes.Proof.Results) != 2 {
		t.Fatal("unexpected number of results provided")
	} else if verRes.Commitments[0] != nil || !bytes.Equal(verRes.Commitments[1], makeBytes(1)) {
		t.Fatal("unexpected commitments returned")
	} else if verRes.Proof.Results[0].Inclusion() || !verRes.Proof.Results[1].Inclusion() {
		t.Fatal("unexpected search result")
	} else if len(verRes.Proof.Elements) != 0 {
		t.Fatal("tree not properly reduced after removal")
	}
}

func TestReplace(t *testing.T) {
	cs := suites.KTSha256P256{}
	store := memory.NewPrefixStore()

	tree := NewTree(cs, store)
	_, _, commitments, err := tree.Mutate(0, []Entry{
		{makeBytes(0), makeBytes(0)},
		{makeBytes(1), makeBytes(1)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	} else if len(commitments) > 0 {
		t.Fatal("unexpected number of commitments returned")
	}
	_, _, commitments, err = tree.Mutate(1, []Entry{
		{makeBytes(0), makeBytes(2)},
	}, [][]byte{makeBytes(0)})
	if err != nil {
		t.Fatal(err)
	} else if len(commitments) != 1 || !bytes.Equal(commitments[0], makeBytes(0)) {
		t.Fatal("unexpected commitment returned")
	}

	res, err := tree.Search([]PrefixSearch{{2, [][]byte{makeBytes(0), makeBytes(1)}}})
	if err != nil {
		t.Fatal(err)
	} else if len(res) != 1 {
		t.Fatal("unexpected number of results returned")
	}
	verRes := res[0]
	if len(verRes.Commitments) != 2 || len(verRes.Proof.Results) != 2 {
		t.Fatal("unexpected number of results provided")
	} else if !bytes.Equal(verRes.Commitments[0], makeBytes(2)) || !bytes.Equal(verRes.Commitments[1], makeBytes(1)) {
		t.Fatal("unexpected commitments returned")
	} else if !verRes.Proof.Results[0].Inclusion() || !verRes.Proof.Results[1].Inclusion() {
		t.Fatal("unexpected search result")
	}
}

func buildRandomTree(t *testing.T, cs suites.CipherSuite) (*Tree, [][]byte, [][]Entry) {
	store := memory.NewPrefixStore()

	tree := NewTree(cs, store)
	roots := make([][]byte, 0)
	allEntries := make([][]Entry, 0)

	for ver := range uint64(100) {
		entries := make([]Entry, 0)
		for range 10 {
			vrfOutput, commitment := randomBytes(), randomBytes()
			entries = append(entries, Entry{vrfOutput[:], commitment[:]})
		}
		root, _, commitments, err := tree.Mutate(ver, entries, nil)
		if err != nil {
			t.Fatal(err)
		} else if len(commitments) > 0 {
			t.Fatal("unexpected number of commitments returned")
		}
		roots = append(roots, root)
		allEntries = append(allEntries, entries)
	}

	return tree, roots, allEntries
}

func TestSearchOneVersion(t *testing.T) {
	cs := suites.KTSha256P256{}
	tree, roots, allEntries := buildRandomTree(t, cs)
	ver := uint64(len(roots))

	// Select a random entry from each version of the tree to search for.
	search := PrefixSearch{Version: ver}
	selected := make([]Entry, 0)
	for _, entries := range allEntries {
		entry := entries[mrand.Intn(len(entries))]
		search.VrfOutputs = append(search.VrfOutputs, entry.VrfOutput)
		selected = append(selected, entry)
	}

	// Execute search.
	res, err := tree.Search([]PrefixSearch{search})
	if err != nil {
		t.Fatal(err)
	} else if len(res) != 1 {
		t.Fatal("wrong number of results returned")
	}
	verRes := res[0]

	// Verify search results.
	if err := Verify(cs, selected, &verRes.Proof, roots[ver-1]); err != nil {
		t.Fatal(err)
	}
	for i, commitment := range verRes.Commitments {
		if !bytes.Equal(commitment, selected[i].Commitment) {
			t.Fatal("unexpected commitment returned")
		}
	}
}

func TestSearchMultipleVersion(t *testing.T) {
	cs := suites.KTSha256P256{}
	tree, roots, allEntries := buildRandomTree(t, cs)

	// For each version of the tree: select a number of random entries from that
	// version or prior versions.
	searches := make([]PrefixSearch, 0)
	entries := make([][]Entry, 0)
	for i := range len(allEntries) {
		vrfOutputs := make([][]byte, 0)
		verEntries := make([]Entry, 0)

		for _, entries := range allEntries[:i+1] {
			entry := entries[mrand.Intn(len(entries))]
			vrfOutputs = append(vrfOutputs, entry.VrfOutput)
			verEntries = append(verEntries, entry)
		}

		ver := uint64(i + 1)
		searches = append(searches, PrefixSearch{ver, vrfOutputs})
		entries = append(entries, verEntries)
	}

	// Execute search.
	res, err := tree.Search(searches)
	if err != nil {
		t.Fatal(err)
	} else if len(res) != len(searches) {
		t.Fatal("wrong number of results returned")
	}

	// Verify search results.
	for i, search := range searches {
		verRes, verEntries := res[i], entries[i]
		if err := Verify(cs, verEntries, &verRes.Proof, roots[search.Version-1]); err != nil {
			t.Fatal(err)
		}
		for i, commitment := range verRes.Commitments {
			if !bytes.Equal(commitment, verEntries[i].Commitment) {
				t.Fatal("unexpected commitment returned")
			}
		}
	}
}

type TestVector2 struct {
	VrfOutputs   []string
	Commitment   string
	Proof        string
	ExpectedRoot string
}

func TestGenerateVectors(t *testing.T) {
	cs := suites.KTSha256P256{}
	tree, roots, allEntries := buildRandomTree(t, cs)

	// Select random VRF outputs to search the tree for.
	selected := make([][]byte, 0)

	// One VRF output that is a proof of inclusion.
	x := mrand.Intn(len(allEntries))
	selected = append(selected, allEntries[x][0].VrfOutput)
	// One VRF output that is a proof of non-inclusion leaf.
	for {
		vrfOutput := make([]byte, cs.HashSize())
		rand.Read(vrfOutput)

		results, err := tree.Search([]PrefixSearch{{
			Version:    uint64(len(allEntries)),
			VrfOutputs: [][]byte{vrfOutput},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := results[0].Proof.Results[0].(nonInclusionLeafProof); ok {
			selected = append(selected, vrfOutput)
			break
		}
	}
	// One VRF output that is a proof of non-inclusion parent.
	for {
		vrfOutput := make([]byte, cs.HashSize())
		rand.Read(vrfOutput)

		results, err := tree.Search([]PrefixSearch{{
			Version:    uint64(len(allEntries)),
			VrfOutputs: [][]byte{vrfOutput},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := results[0].Proof.Results[0].(nonInclusionParentProof); ok {
			selected = append(selected, vrfOutput)
			break
		}
	}

	// Search for those VRF outputs.
	results, err := tree.Search([]PrefixSearch{{
		Version:    uint64(len(allEntries)),
		VrfOutputs: selected,
	}})
	if err != nil {
		t.Fatal(err)
	}

	// Serialize test vector.
	vrfOutputs := make([]string, len(selected))
	for i, vrfOutput := range selected {
		vrfOutputs[i] = fmt.Sprintf("%x", vrfOutput)
	}
	buf := new(bytes.Buffer)
	if err := results[0].Proof.Marshal(buf); err != nil {
		t.Fatal(err)
	}
	vector := TestVector2{
		VrfOutputs:   vrfOutputs,
		Commitment:   fmt.Sprintf("%x", allEntries[x][0].Commitment),
		Proof:        fmt.Sprintf("%x", buf.Bytes()),
		ExpectedRoot: fmt.Sprintf("%x", roots[len(roots)-1]),
	}
	t.Logf("%#v", vector)

}

func mustDecode(x string) []byte {
	raw, err := hex.DecodeString(x)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestVectors2(t *testing.T) {
	cs := suites.KTSha256P256{}
	vectors := []TestVector2{
		{VrfOutputs: []string{"b382aaa828f788911f63a45525cc8e0bd44fb16a30eacd255aa2dbcdc2eb0e52", "94f5b54b09671f24bf79cf77ef440956bfda4db07cdfc3bc7819e213181c2826", "eb456fadb909ffe7d725a23d72ce31a363aad55e96320e44912fa5a6057cfc16"}, Commitment: "c9ca5295598b01ee700020b841fbe98556024a32ccf0932ab59b4692a2fd3af5", Proof: "0301090294faf0b051d7621a013f90b7e226b579629bbfc160552aeaafd6ecbd485f3bebf2f57e812437e009673f525e372a9d85886be197d7cf85f62aeea35c6166a8700b030d001a3f9ec731714613f2da94f9b647eeecfa64f9e941638f0ebaf066051f7ba4976a9198aebb3db4b39c1b57834932e02fda7cf5d7a7a473cf29f4746ae0d90af0832e5bdb40d4581154d05611a3522b4dd92c52829331065e4b4b858a6f822e53240000000000000000000000000000000000000000000000000000000000000000b2e91f9f7199c3da81bd6b94d817046eb8ac7c83624c132859ca87305d2d8ed65c06488e0c0f588e74574613fa2eb6428cbdba31fb7eb86f2e5d590d3460ce000ea1a1c321d0ac832eba5df5267d2e7868d1b9885c8b8e3cde6bf4a7f160c4644162c98baf7e7d537e90c2e54e5d91bba081d255cb17cabc2d7760f594462dcf49474a1d0bdfb4b446ae8cc0e8e20ff1dd8868f8e42df304939fa1af5f7d0a5d9906632c83941296f97a460e5580f7c4d0fca01d9ae3b0e46a4383e26832e9dac9aa7141dcc9904287615920721580ff0032cc94507a3afa898128ac17517fa5032ba1f4ebbc16cb23e2a412e67e37aeea94218b1d85b68d17d9c199054593ef9e67228b4271559778cc39cdccb779eb5d207cb07db3bfa4d36ba5441da26608f3a63d10b85d47fa299877f63921620da3a7beb75183a9912e3882ff36920c54a104e8f158f5c2f51c4ac07426bed6c51633ccb04d9f40c6ef800f5450b2379cc1169f1500c9c58f4d72a90469c2f1009658230c6bc781efffe68bf4fe73f7f975427f15e22759f9f0198feba0b27f16c970dd8127ba4a8197a12f283572eb9aaf7865c9ccc971a048bac998b2fb5bff4118df546f8ebfc213f937e3e3ada04ab0284fe17fc8df974f0e9fa4ca1d291c9670c19abcf1a351993a06c9e168f74dfa41271d99811bb995bdb3238f21049efcf1ffd86f68ed5e69ef3386200225ecbedfe06008615e3a4b885990a1db4cf6cfc47e69dd0019ea1d09ff80bf94c7070000000000000000000000000000000000000000000000000000000000000000a92c836630b8b41476264b0291cf4123e752c452f3044a6468b972268fc228a748473cf920cdcc3da9c487e933278e346e2d7f8175a51682405a0c8d509c5649a8eb37a905cfe0da3f9a3a0ccd64fe48dbb8442e8cab89e2990fc7f6e9f780a30bb4bce40c3a99c6e569e8aab7efac84916ff4dfa436977234addc95b93a9772", ExpectedRoot: "f8f52f19f625e74feb0c3b89d3c8ddbacf001fe906cc904cb5e89ec12d49cad9"},
		{VrfOutputs: []string{"88be8b76c565d0f24301b9da4c43764ba4a515a92717b855a56a54f56a489d62", "7db84e5158a91026200e1334cf967560b37f1491262b636046e92186de7ea4de", "b477e2b01ffe539ff0d7940b25febcd356b3bf813782eb3da2c95e4b81fbe45c"}, Commitment: "46b325291299d8e33671c85820136ed9046726d8af51616f71b42011441f9a45", Proof: "030109027d903f2e4d0e8c2c7e4ec47491f375f902120b57ddb3dbbb1cf00cc73a7682f2f9d5ffb455b1529c591df43672507e7d8f889c6c64d761323ed830d99f46a8540a030800153c42bd3589b6c86561d2552dd537c7dcbd7a0886a81a320e129ef00953b205b02141c34387dcbfc5c4a0a7479e9a1d10980202aa1b7f294e560834ae96979d79ab912c1d64e0ef2748dd360fb343e21aa38b2e5ab749fa5037b9cd0715c7af20d2350dc5d8470a6f8b59ae991ac862b7bf8d473e22c614f441276f978fc33f24b87824bbfa30d90d9f75db0ac9b10f223a84998b37a9c2426a8301bc92bd3102345a3004276185d87259f97102894a0a87e9eec1bcda3530f5135c45f6c8dde88825686a97e88c20bc82ae3508fa5aa101a7c8e719f6ed4bb4cffe53087fc59d1eb240f3bef6171c8278aba4e09b2d696e205fe87dbdfde93e6d2c429dfb79f6fad7f9c67bb9a36b242e96931883ec59b0ebd5ed9be522e2a2c3ec6e98a0cdd06217f704350668958fe7e776bd8912897a3d29dc1d73facc7b6f3d53dccf90e9776329469205bed9470dc612bc8ce8f322025472c67bbabdaf5ade50cf29c8bf346cac1e742d651a3de6485abb6138015dae6eb3147fdce3e8bb3a4eda0a94fa4651a6f39b50ebc3e1f6b5c48024e56786ab3237e08e6067f4eeb122fbefbc0f48c989b748acf3e6d4500d4952c3841921e0071906e612cdf379121a916cebff35feb2eac55e706fe153d2ae50ff931fea2049f7727d5cf2fb26a4204c854a4a1edbb4ab51f38b3e2554abd2466e55b42bdfc5d66c1943f8bd820ba6c3bd9dd1bd1f32a82bf490523d35fdf77f7943a4512f4bd533bc83422f440130e3da65d8f1adb57f75c1aaeb6cb726cd1a3b66636411b3bf69e8877158c1142d622c057915972b94b91a6dd3298800e8f92d1c1818d690afd00479acd1e2c7903e5cc0d554583fe012e0850d0b9fecbd5b077bc8912027ce10cf7f2fa8589a13f0f9222dd076995fac72d8ed5fc2d86fe709fff0a2ba24595ad31b8cbefbdaea5b3e19ec", ExpectedRoot: "dbaa826d1cc39c35b3df4c81436252b39788cede4ebbceb4ceaac1028f535870"},
		{VrfOutputs: []string{"cefdf1889174fae7ab96008ef5531cf01d5bae317931867c9c67d4dfff0d1c37", "cf00758b9bd1a01f35bc1b70c3da5ca49e9380de5647cc39e76dff13f302e1db", "47e7fead3dcb63c8013c80ebbd5352e7aaf27796d55ae60a8826c4958230242c"}, Commitment: "ff24aec7948efa84e877f7823049dd51d2c32dfe991d3e5aaa7d1629713cc10e", Proof: "03010c02cf4b08c41cbf2cb6b85b459335ecda1feae2cbe19830124151ba47272c89a05062e5877f708258afe803998476257bd0fe010f18101bf3afab8ff96f9ad3b2fa09030a0014e0806fa5ba1b249d44e7b73e1d9766a2816039b682ff582cdf7f5e8bc075738f9827e32edad45039f3f08af607203b778dad76acdc593d3ea972be62101df9ffd05379b56fc844fe63011ba6e3d8236bbc6c1a509fb1e46854e1c4572c97543f155bf416b369e50ee9f8586e524053088d800e88d388d89f678abdd8cfe7d01e9951316043f03d04140a99a58643fbea6e27163b291d55eb20b7029bdf2cf5cc4beae9404d3ae66b4fbce78c483276428af274a3696ad912eb3dea6a85b074cfe6304ad0920154e45dabb257d5a9a6654c988992c57202d6236246c4d5dab3c50b4e6151aae0cacef8897b888d3903772107121cead5fd47d2828287e48ee0c14818c62c0308fcaf8c214b67840a164ea60cf35ad2c21db07ff338736d413196b5413cad01d7be4b1fa07f155d55fbaf3000d66601ffa8aba01cdd6f1d681c629fe6ee20c938c31c5c518578f6e2a87e77655d3d47f1e40d0c764371e05c4707b2f338c8e0a64d3720a7ef38815bb909d102ab860da027e98fc59be274e6f8b309b358286868b3038ab8d5161d2f203fa27a3bcbed9cee4de9ecf9c0e31d69e13dea723f625b44a07c3c7f9316372410e4a4743a31ac8a720a9f3ffda6c334016e4ac7f12ff1cf12064689c857d193e816b2a674f1205352697dbd22504a29c358921c10432924deedfa980eccfdb33b684b07f22e0d65f6b8c346fd62a80f2dd9b252b804f1efb9140b8ec6395d64d178ae6904baaca37bca33c9d9bda0e9387e0b5104eac0c79944eb2994d6c520cd22fabdeb62e714257debfbdb23b0e3b3e0f289f665948aa8db5d5dff8a0e59ac4bdfcaeaed37910353bedbcdf113b0209bbcfd6d6c431fd4bd4156540e118b90bb400035da0dd8ab0604fbd70ec541ed", ExpectedRoot: "3629d6b6c6f12764ccabd793eff428f8b1ae3c3017fc3749b4607ff4b4af05a9"},
	}

	for _, vector := range vectors {
		entries := make([]Entry, 0)
		for _, vrfOutput := range vector.VrfOutputs {
			entries = append(entries, Entry{VrfOutput: mustDecode(vrfOutput)})
		}
		entries[0].Commitment = mustDecode(vector.Commitment)

		proof, err := NewPrefixProof(cs, bytes.NewBuffer(mustDecode(vector.Proof)))
		if err != nil {
			t.Fatal(err)
		}
		err = Verify(cs, entries, proof, mustDecode(vector.ExpectedRoot))
		if err != nil {
			t.Fatal(err)
		}

	}
}
