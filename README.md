# Katie: Transparency Server

Key Transparency (KT) is a safe, publicly-auditable way to distribute public
keys for end-to-end encryption. More generally, the same technology can also be
used for tamper-evident logging, key usage detection, ensuring that a group of
users agree on a shared value, and many other applications.

## Usage

Run the `generate-keys` command to generate a new set of private keys for your
server:

```
go run github.com/Bren2010/katie/cmd/generate-keys
```

Write a config file that contains the private keys you just generated, that
looks like:

```
server-addr: :8080
metrics-addr: :8081
api:
  home: https://www.example.com/
  signing-key: 95ce4eae22d9e54fde1da4e90359d42d068978233913583fee07b180500270ed
  vrf-key: |
    -----BEGIN VRF PRIVATE KEY-----
    MHcCAQEEIIQ/qJ0hUZ7oJ6I9UMkSCzA9Mp2/TLIuxxMj3VTai1l0oAoGCCqGSM49
    AwEHoUQDQgAEy4bKBRB5u+Msy8wOqvW9GOPd1EFbLgvO1z2U37B1r9ThAg8DzneU
    eiNV8Ue/A5a5/siVZ4OZFiFLlvz1VPcGBA==
    -----END VRF PRIVATE KEY-----

db-file: ./db
```

And run the server:

```
go run github.com/Bren2010/katie/cmd/katie-server -config ./config.yaml
```

You can now access metrics at `localhost:8081/metrics` and the transparency
server itself at `localhost:8080`. The transparency server exposes the following
endpoints:

- `GET /v1/meta`: Returns basic information about the log.
- `GET /v1/consistency/[older]/[newer]`: Returns a consistency proof between two versions of the log.
- `GET /v1/account/[name]`: Searches for the account with the given name and outputs a proof of inclusion/non-inclusion.
- `POST /v1/account/[name]`: Sets the value of the specified account to be the POST request body, and returns a proof.

## Documentation

More information is available in the `docs/` folder, and you can also read these
academic papers for background:

- [Merkle^2: A Low-Latency Transparency Log System](https://eprint.iacr.org/2021/453)
- [CONIKS: Bringing Key Transparency to End Users](https://eprint.iacr.org/2014/1004)
