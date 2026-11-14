# caddycertkeeper

[![CI](https://github.com/AndrianBdn/caddycertkeeper/actions/workflows/ci.yml/badge.svg)](https://github.com/AndrianBdn/caddycertkeeper/actions/workflows/ci.yml)

S3 storage for [Caddy](https://caddyserver.com) and [CertMagic](https://github.com/caddyserver/certmagic). It keeps certificates, private keys and ACME accounts in an S3-compatible bucket, shares them between Caddy instances, and can encrypt them before they leave Caddy.

caddycertkeeper is a fork of [techknowlogick/certmagic-s3](https://github.com/techknowlogick/certmagic-s3) and a **drop-in replacement** for it: the same plugin, just better maintained. **As of November 2026 it is the most actively maintained version of this plugin, with fixes that have not landed anywhere else.**

```sh
xcaddy build --with github.com/AndrianBdn/caddycertkeeper
```

## Switching from certmagic-s3

Change the build, not the config or the bucket:

```diff
- xcaddy build --with github.com/techknowlogick/certmagic-s3
+ xcaddy build --with github.com/AndrianBdn/caddycertkeeper
```

- The Caddy module is still `caddy.storage.s3`, so existing Caddyfiles and JSON configs keep working. Build only one of the two plugins into a Caddy binary.
- Every option keeps its name and meaning.
- The bucket layout, the locks and the encryption format are unchanged, so each plugin reads what the other wrote. The exception is the new `base64:` [key format](#generating-a-key), which certmagic-s3 does not know.

What you will notice after the switch:

- **Expired certificates get deleted.** The first storage clean removes certificates that expired more than two weeks ago, with their private keys. certmagic-s3 never removed them.
- **A different ACME account may be picked.** With no account email configured and several accounts in the bucket, CertMagic now uses the most recently used one, as it does on disk.
- **Config mistakes are errors.** A Caddyfile option with no value, with too many values, or an unknown word on its own line fails with the line number. A bare `insecure` used to do nothing; write `insecure true`. A JSON config without `bucket` fails too.
- **`host` works in JSON.** A JSON config with `host` and no `endpoint` now talks to that host. Before, `host` was ignored there and requests went to AWS.

## What is fixed and added

Compared to certmagic-s3 v1.5.0:

- **Secrets stay out of the log.** CertMagic logs its storage on every storage clean. With certmagic-s3 that line contains `access_key`, `secret_key` and `encryption_key` in plain text ([certmagic-s3#28](https://github.com/techknowlogick/certmagic-s3/issues/28)).
- **Folder listings work.** certmagic-s3 answered every folder listing with all the files below it, so expired certificates were never cleaned up and ECH configs were regenerated on every reload ([certmagic-s3#26](https://github.com/techknowlogick/certmagic-s3/pull/26)). Listing, `Stat`, `Exists` and `Delete` now behave like CertMagic's own file storage.
- **Key rotation.** `encryption_key` takes the current key followed by old ones, and objects are re-encrypted as they are read. See [Rotating the key](#rotating-the-key).
- **Stronger keys.** A key can be 32 random bytes written as `base64:...`, not only 32 characters of text. See [Generating a key](#generating-a-key).
- **Keys from a file or from AWS SSM Parameter Store**, so the key is not in the config. See [Key in a file](#key-in-a-file) and [Key in SSM Parameter Store](#key-in-ssm-parameter-store).
- **Config mistakes are reported**, not silently skipped.
- **`insecure` only turns off certificate verification.** It no longer drops the proxy settings and timeouts of the HTTP client.
- Current dependencies (Caddy v2.11.9), a working lint config, and CI.

## Configuration

Only `bucket` is required.

| Option | Meaning |
| --- | --- |
| `bucket` | Bucket name. |
| `region` | AWS region. Defaults to `us-east-1`. |
| `prefix` | Prefix of every object key. Defaults to `acme`. |
| `endpoint` | Endpoint URL of an S3-compatible provider. Turns on `use_path_style`. |
| `use_path_style` | `true` for path-style URLs. |
| `insecure` | `true` to skip TLS certificate verification. |
| `access_key`, `secret_key` | Static credentials. |
| `profile` | AWS shared config profile. |
| `role_arn` | IAM role to assume. |
| `encryption_key` | Encryption key, optionally followed by old keys. See [Encryption](#encryption). |
| `encryption_key_file` | Files holding the encryption keys. |
| `encryption_key_ssm` | SSM parameters holding the encryption keys. |
| `host` | Deprecated, use `endpoint`. Giving both is an error. |

Without `access_key`/`secret_key` or `profile`, the AWS SDK's default credential chain is used: environment variables, shared config, and the ECS task or EC2 instance role.

Without an encryption key option, objects are stored in plain text.

```caddyfile
{
  storage s3 {
    bucket "my-certificates"
    region "eu-central-1"
    prefix "caddy-certs"
    encryption_key_ssm "/caddy/cert-encryption-key"
  }
}
```

An S3-compatible provider with static credentials:

```caddyfile
{
  storage s3 {
    endpoint "https://minio.example.com"
    bucket "my-certificates"
    access_key "minioadmin"
    secret_key "minioadmin"
    encryption_key "base64:<output of openssl rand -base64 32>"
  }
}
```

### Environment variables

Any option can take its value from the environment with Caddy's [`{$VAR}` substitution](https://caddyserver.com/docs/caddyfile/concepts#environment-variables). `{$VAR:default}` gives a default for when the variable is unset.

```caddyfile
{
  storage s3 {
    bucket "{$CERT_BUCKET}"
    region "{$AWS_REGION:eu-central-1}"
    encryption_key "base64:{$CERT_KEY}"
  }
}
```

- **Encryption key:** use the `base64:` form shown above. See [Key in an environment variable](#key-in-an-environment-variable) for why.
- **Credentials:** these need no option. The AWS SDK reads `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_PROFILE` by itself.
- **Region:** in a Caddyfile, `AWS_REGION` is not picked up by itself, because `region` defaults to `us-east-1`. Pass it on as above.
- **Bucket:** an unset variable leaves `bucket` empty, which is an error.

### JSON config

The options have the same names. Old keys go in `old_encryption_keys`, and `encryption_key_file` and `encryption_key_ssm` are lists.

`{$VAR}` is a Caddyfile feature. A JSON config gets no substitution, and `{env.VAR}` placeholders are not expanded. To keep the key out of a JSON config, use `encryption_key_file` or `encryption_key_ssm`.

Three defaults differ from the Caddyfile. They are the same as in certmagic-s3, so that existing JSON setups keep finding their objects:

- An empty `prefix` means the root of the bucket, not `acme`.
- A custom endpoint does not turn on `use_path_style`. Set it yourself if the provider needs it.
- An empty `region` is taken from the environment or the shared AWS config, and is `us-east-1` only when nothing names one.

## Encryption

With a key, every object is sealed with NaCl secretbox (XSalsa20-Poly1305) under a fresh random nonce before it leaves Caddy.

The key comes from one of `encryption_key`, `encryption_key_file` or `encryption_key_ssm`; they cannot be combined. Each takes the current key first, optionally followed by old keys. Keys are read when Caddy starts or reloads its config.

### Generating a key

Generate the key, do not invent it:

```sh
echo "base64:$(openssl rand -base64 32)"
```

The output is a key of 32 random bytes. Use it as the value of `encryption_key`, as the content of a key file, or as the value of an SSM parameter. Both base64 alphabets are accepted, with or without padding, and the value needs no quoting in a Caddyfile.

### 32-character keys from certmagic-s3

A certmagic-s3 key is exactly 32 characters, and those characters are the key as they are. They are not decoded from hex or base64, and not stretched from a passphrase. Such keys keep working here, but a key is only as strong as it is random:

| How the key was made | Randomness |
| --- | --- |
| `base64:` with `openssl rand -base64 32` | 256 bits |
| 32 characters from `openssl rand -base64 24` | 192 bits |
| 32 characters from `openssl rand -hex 16` | 128 bits |
| 32 characters someone made up | far too little |

The generated ones are all beyond guessing. A made-up phrase is not: anyone who obtains the bucket's contents can try phrases offline. If your key is one of those, rotate to a generated one.

certmagic-s3 cannot read `base64:` keys. Once objects are under one, only caddycertkeeper can read the bucket.

### Rotating the key

Put the new key first and keep the old one after it:

```caddyfile
encryption_key "base64:<new key>" "<old key>"
```

The first key encrypts everything that is written, and every key is tried when reading. An object that is read and turns out to be under an old key is stored again under the current one, and each rewrite is logged:

```json
{"level":"info","logger":"caddy.storage.s3","msg":"re-encrypted object under the current encryption key","key":"caddy-certs/acme/.../admin.key"}
```

The rewrite is a conditional write (`If-Match` on the version that was read). It needs no lock and never replaces what another instance stored in the meantime.

Instances that share a bucket need two rollouts, because an instance that only has the old key cannot read what another one wrote under the new key:

1. Roll out `<old> <new>` to every instance. All of them read both keys and still write under the old one.
2. Roll out `<new> <old>` to every instance. All of them write under the new key.

Until step 2 has reached every instance, the ones still on step 1 may rewrite objects back under the old key. That settles once all are on step 2.

Remove the old key when rewrites have stopped appearing in the log. Objects Caddy never reads, such as the certificate of a site that is no longer configured, stay under the old key until they are cleaned up as expired.

### Key in an environment variable

Put the output of `openssl rand -base64 32` in the variable, without `base64:`, and write the prefix in the Caddyfile:

```caddyfile
encryption_key "base64:{$CERT_KEY}"
```

- **An unset variable is an error.** Caddy refuses the config with `encryption key must be the base64 of exactly 32 bytes, got 0`.
- **Do not put the whole key in the variable** and write `encryption_key "{$CERT_KEY}"`. If the variable is ever unset, the option is empty, and objects are stored in plain text without any error.
- **A 32-character key** cannot take the prefix. Write it without quotes, `encryption_key {$CERT_KEY}`, which is an error when the variable is unset.
- **Rotation** works the same way: `encryption_key "base64:{$CERT_KEY}" "base64:{$CERT_KEY_OLD}"`.

The substituted key becomes part of the adapted config: `caddy adapt` prints it, the admin API returns it, and Caddy saves it to disk with the rest of its last config. A key in a file or in SSM stays out of all three.

### Key in a file

```caddyfile
encryption_key_file "/run/secrets/caddy-cert-key"
```

- The file holds one key, written as for `encryption_key`. A line ending at the end of the file is ignored.
- A file of exactly 32 bytes is used as the key itself, so the raw output of `openssl rand -out <file> 32` works as well.
- Only the user Caddy runs as should be able to read the file (`chmod 600`).

### Key in SSM Parameter Store

```caddyfile
encryption_key_ssm "/caddy/cert-encryption-key"
```

Each parameter holds one key, written as for `encryption_key`, preferably as a `SecureString`:

```sh
aws ssm put-parameter --type SecureString --name /caddy/cert-encryption-key \
  --value "base64:$(openssl rand -base64 32)"
```

- Parameters are named by name or ARN, and read with the region and credentials configured for the bucket. A parameter given by ARN is read from the region in its ARN.
- A version or label works too, which makes rotation a matter of writing a new version: `encryption_key_ssm "/caddy/cert-encryption-key:2" "/caddy/cert-encryption-key:1"`.
- The identity Caddy runs as needs `ssm:GetParameter` on the parameters, and `kms:Decrypt` if the SecureString uses a customer managed KMS key.
- Keys are only read from AWS itself, over verified TLS. `endpoint`, `insecure` and endpoint overrides such as `AWS_ENDPOINT_URL` do not apply to SSM.
- With keys in SSM, `insecure` covers the bucket connection only, so the credentials that can read the keys are fetched over verified connections too.

## S3-compatible services

The service must support:

- v4 signatures
- GetObject, PutObject, DeleteObject, HeadObject and ListObjectsV2
- conditional writes on PutObject (`If-None-Match: *` and `If-Match`), which the cross-instance lock and key rotation rely on

## Development

```sh
make test       # go test ./...
make test-race  # with the race detector
make lint       # golangci-lint v2
make fmt        # gofumpt
```

CI runs the tests with the race detector on the two current Go releases, and the linter. There is nothing to build or release: the plugin is compiled into Caddy by `xcaddy`.

## Credits & thanks

caddycertkeeper stands on other people's work, and it would not exist without them:

- [@techknowlogick](https://github.com/techknowlogick), who maintained [certmagic-s3](https://github.com/techknowlogick/certmagic-s3) for years, moved it to the AWS SDK and kept it working across many Caddy and CertMagic releases. This fork starts from certmagic-s3 at commit [`6c26852`](https://github.com/techknowlogick/certmagic-s3/commit/6c26852) (October 2026), with all of that history behind it.
- [@thomersch](https://github.com/thomersch), who wrote the original [Certmagic Storage Backend for Generic S3 Providers](https://github.com/thomersch/certmagic-generic-s3), including the client-side encryption this plugin still uses.
- Everyone who reported bugs and sent fixes to both projects, among them the people behind the storage-clean fix and the rewrite of the cross-instance lock.

Thank you. The fork exists only to ship fixes faster, not because anything was wrong with the work it builds on.

## License

[Apache 2.0](LICENSE), the same as the projects it is forked from. The changes made in this fork are listed under [What is fixed and added](#what-is-fixed-and-added).
