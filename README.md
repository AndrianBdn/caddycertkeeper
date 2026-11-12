# caddycertkeeper

[![CI](https://github.com/AndrianBdn/caddycertkeeper/actions/workflows/ci.yml/badge.svg)](https://github.com/AndrianBdn/caddycertkeeper/actions/workflows/ci.yml)

S3 storage for [Caddy](https://caddyserver.com) and [CertMagic](https://github.com/caddyserver/certmagic): keep certificates, private keys and ACME accounts in any S3-compatible bucket, share them between instances, and optionally encrypt them on the client with [secretbox](https://pkg.go.dev/golang.org/x/crypto/nacl/secretbox).

caddycertkeeper is a fork of [techknowlogick/certmagic-s3](https://github.com/techknowlogick/certmagic-s3). **As of November 2026 it is the most actively maintained version of this plugin, with fixes that have not landed anywhere else.**

## Drop-in replacement for certmagic-s3

caddycertkeeper is a drop-in replacement for `techknowlogick/certmagic-s3`. It is the same plugin, just better maintained:

- the Caddy module is still `caddy.storage.s3`, so `storage s3 { ... }` in a Caddyfile and `"module": "s3"` in JSON keep working;
- every existing option keeps its name and meaning;
- the bucket layout, the lock objects and the encryption format are unchanged, so it reads what certmagic-s3 wrote, and the other way round. (The other way round holds for as long as you keep a key certmagic-s3 can be given: it does not know the `base64:` keys [recommended below](#generating-a-key).)

Switching is a change to the build, not to the config or the bucket:

```diff
- xcaddy build --with github.com/techknowlogick/certmagic-s3
+ xcaddy build --with github.com/AndrianBdn/caddycertkeeper
```

Build only one of the two into a Caddy binary: both register `caddy.storage.s3`.

Two things behave differently after the switch, both because folder listings now work:

- The first storage clean removes certificates that expired more than two weeks ago (Caddy's grace period), together with their private keys and metadata.
- If no ACME account email is configured and the bucket holds more than one account for a CA, CertMagic now picks the most recently used one, as it does on disk. Before, it could not see the accounts and used the default one.

And a config with a mistake in it, which certmagic-s3 loaded while skipping the mistake, is now refused with an error that names the line:

- In a Caddyfile: an option with no value (`insecure` on a line of its own did nothing; write `insecure true`), an option with more values than it takes, or an unknown word on a line of its own.
- In JSON: a config without `bucket`. A JSON config with `host` and no `endpoint` now talks to that host; before, `host` was ignored there and requests went to AWS.

## What is fixed and added here

Compared to certmagic-s3 v1.5.0:

- **Secrets are no longer written to the log.** CertMagic logs its storage on startup and on every periodic storage clean (`"msg":"cleaning storage unit"`). With certmagic-s3 that line carries the whole config: `access_key`, `secret_key` and `encryption_key` in plain text ([certmagic-s3#28](https://github.com/techknowlogick/certmagic-s3/issues/28)). caddycertkeeper logs the endpoint, bucket, region and prefix, and nothing secret.
- **Expired certificates are cleaned up, and ECH configs survive a reload.** Caddy and CertMagic walk the storage folder by folder, and certmagic-s3 answered every such listing with all the files below, at any depth. As a result expired certificates and their private keys were never removed from the bucket, and with Encrypted ClientHello enabled every reload discarded the stored ECH configs and generated new ones ([certmagic-s3#26](https://github.com/techknowlogick/certmagic-s3/pull/26)). Listing, `Stat`, `Exists` and `Delete` now treat a key that other keys lie under as a folder, the way CertMagic's own file storage does; the tests compare the two directly.
- **Encryption key rotation.** `encryption_key` takes the current key followed by any number of old ones, and objects still under an old key are re-encrypted as they are read. Changing the key no longer means emptying the bucket and reissuing every certificate. See [Rotating the encryption key](#rotating-the-encryption-key).
- **Encryption keys of 32 random bytes.** certmagic-s3 uses the 32 characters of `encryption_key` as the key, as they are, so a key can only be as random as 32 characters of text. A key can now be written as `base64:` followed by the base64 of 32 random bytes; 32-character keys keep working unchanged. See [Generating a key](#generating-a-key).
- **Encryption keys from AWS SSM Parameter Store.** `encryption_key_ssm` reads the keys from SecureString parameters, so the key is in neither the Caddyfile nor Caddy's JSON config. See [Keeping the key in SSM Parameter Store](#keeping-the-key-in-ssm-parameter-store).
- **Encryption keys from files.** `encryption_key_file` reads the keys from files, such as a mounted Docker or Kubernetes secret. See [Keeping the key in a file](#keeping-the-key-in-a-file).
- **Config mistakes are reported, not skipped.** A Caddyfile option without a value was silently dropped, so a bare `insecure` or a line cut short changed nothing and said nothing. JSON configs skipped the checks altogether: `host` was ignored and a missing `bucket` only surfaced as failing requests.
- **`insecure` only turns off certificate verification.** It used to replace the whole HTTP transport with a bare one, which dropped the proxy settings from the environment and every timeout, so idle connections could stay open after each config reload.
- Dependencies are current (Caddy v2.11.9), the lint configuration is valid for golangci-lint v2 again, and the Dockerfile uses a Caddy builder image new enough for the Go version the module needs.

## Building

```sh
xcaddy build --with github.com/AndrianBdn/caddycertkeeper
```

## Configuration options

- `bucket`: S3 bucket name (required)
- `region`: AWS region (optional, defaults to `us-east-1`)
- `prefix`: object key prefix (optional, defaults to `acme`)
- `endpoint`: custom endpoint URL, for S3-compatible providers (optional)
- `host`: **deprecated**, use `endpoint` instead. Giving both is an error.
- `use_path_style`: force path-style URLs (optional, always `true` when a custom endpoint is used)
- `insecure`: skip TLS certificate verification (optional, defaults to `false`)
- `access_key`, `secret_key`: static credentials (optional)
- `profile`: AWS shared config profile (optional)
- `role_arn`: IAM role to assume (optional)
- `encryption_key`: key for client-side encryption, optionally followed by old keys (optional; without a key, objects are stored in plain text). Written as `base64:` and the base64 of 32 random bytes, see [Generating a key](#generating-a-key); a 32-character key as certmagic-s3 takes it works too.
- `encryption_key_file`: paths of files holding the encryption keys, instead of `encryption_key` (optional)
- `encryption_key_ssm`: names or ARNs of SSM parameters holding the encryption keys, instead of `encryption_key` (optional)

Without `access_key`/`secret_key` or `profile`, the AWS SDK's default credential chain is used: environment variables, shared config, and the ECS task or EC2 instance role.

In JSON config the options have the same names; old keys go in `old_encryption_keys` (a list), and `encryption_key_file` and `encryption_key_ssm` are lists. Three defaults are different there, and stay as they are in certmagic-s3 so that existing JSON setups keep finding their objects:

- an empty `prefix` means the root of the bucket, not `acme`;
- `use_path_style` is not switched on by a custom endpoint, set it yourself if the provider needs it;
- an empty `region` is taken from the environment or the shared AWS config, and is `us-east-1` only when nothing names one.

## Configuration examples

### AWS S3 with static credentials

```caddyfile
{
  storage s3 {
    bucket "my-certificates"
    region "us-west-2"
    access_key "AKIAEXAMPLE"
    secret_key "EXAMPLE"
    prefix "caddy-certs"
    encryption_key "base64:<output of openssl rand -base64 32>"
  }
}
```

### AWS S3 with an instance role and the key in SSM

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

### S3-compatible provider

```caddyfile
{
  storage s3 {
    endpoint "https://minio.example.com"
    bucket "my-certificates"
    region "us-east-1"
    access_key "minioadmin"
    secret_key "minioadmin"
    prefix "caddy-certs"
  }
}
```

## Encryption

With an encryption key, every object is sealed with NaCl secretbox (XSalsa20-Poly1305) before it leaves Caddy, under a fresh random nonce. The key is exactly 32 bytes, and comes from one of three places: the config (`encryption_key`), files (`encryption_key_file`) or SSM Parameter Store (`encryption_key_ssm`).

### Generating a key

Generate the key, do not invent it:

```sh
echo "base64:$(openssl rand -base64 32)"
```

The output is the value for `encryption_key`, for an SSM parameter, or for a key file:

```caddyfile
encryption_key "base64:<the 44 characters from openssl>"
```

`base64:` is followed by the base64 of exactly 32 bytes. Both base64 alphabets are read (`+/` and `-_`), with or without the `=` padding, and none of these characters needs quoting in a Caddyfile.

### 32-character keys

certmagic-s3 takes a key of exactly 32 bytes of text, and those 32 bytes are the key, as they are. Nothing decodes them from hex or base64: `0123456789abcdef0123456789abcdef` is a key of 32 ASCII characters, not of 16 bytes. Such keys keep working here, unchanged, and a value of exactly 32 bytes is always read this way, whatever it starts with.

In neither form is the key stretched: there is no password hashing between what you configure and the cipher, so a key is only as strong as it is random. That is where the two forms differ:

| How the key is made | Randomness |
| --- | --- |
| `base64:` and `openssl rand -base64 32` | 256 bits |
| 32 characters from `openssl rand -base64 24` | 192 bits |
| 32 characters from `openssl rand -hex 16` | 128 bits |
| 32 characters someone made up | far too little |

The generated ones are all far beyond guessing. A made-up phrase is not: anyone who obtains the bucket's contents can try phrases offline, as fast as their hardware allows. If your key is one of those, [rotate](#rotating-the-encryption-key) to a generated one.

A 32-character key rewritten as `base64:` and the base64 of those characters is the same key, no stronger than before. `base64:` keys are not understood by certmagic-s3, so once objects are under one, the bucket can only be read with caddycertkeeper.

### Rotating the encryption key

`encryption_key` accepts a list: the first key encrypts everything that is written, and every key in the list is tried when reading.

```caddyfile
encryption_key "base64:<new key>" "the-old-32-character-key-as-is!!"
```

For a single instance, or instances that each have their own bucket or prefix, that is the whole rotation: put the new key first, keep the old one after it, reload.

Instances that share a bucket need two steps, because an instance that only knows the old key cannot read what another one wrote under the new key:

1. Roll out `encryption_key <old> <new>` to every instance. All of them can now read both keys and still write under the old one.
2. Roll out `encryption_key <new> <old>` to every instance. All of them now write under the new key.

While an old key is listed, every object that is read and turns out to be under an old key is stored again under the current one. Each rewrite is logged:

```json
{"level":"info","logger":"caddy.storage.s3","msg":"re-encrypted object under the current encryption key","key":"caddy-certs/acme/.../admin.key"}
```

The rewrite is a conditional write (`If-Match` on the version that was read), so it never replaces what another instance stored in the meantime, and it needs no lock. If it fails, the read still succeeds and the object is tried again the next time it is read.

Keep the old key in the list until everything has been rewritten. Caddy reads the certificates it manages when it starts and its ACME account when it obtains or renews one, so what is in use moves to the new key quickly; an object Caddy never reads, such as the certificate of a site that is no longer configured, stays under the old key until it is cleaned up as expired. Remove the old key when the rewrites have stopped appearing in the log and nothing you still need predates the rotation.

While step 2 is being rolled out to instances that share a bucket, the ones still on step 1 treat the new key as the old one and may rewrite objects back; that settles once every instance is on step 2.

### Keeping the key in a file

`encryption_key_file` takes the paths of files instead of the keys themselves. Each file holds one key. As with `encryption_key`, the first one encrypts and the rest are old keys:

```caddyfile
encryption_key_file "/run/secrets/caddy-cert-key" "/run/secrets/caddy-cert-key-old"
```

- A file holds one key as it would be written for `encryption_key`: `echo "base64:$(openssl rand -base64 32)" > /etc/caddy/cert.key`. One line ending at the end of the file is ignored.
- A file of exactly 32 bytes is the key itself, whatever the bytes are, so the raw output of `openssl rand -out /etc/caddy/cert.key 32` works as well.
- The files are read once, when Caddy starts or reloads its config. Reload Caddy after changing a file.
- Only the user Caddy runs as should be able to read the files (`chmod 600`).
- `encryption_key_file` cannot be combined with `encryption_key` or `encryption_key_ssm`.

### Keeping the key in SSM Parameter Store

`encryption_key_ssm` takes the names (or ARNs) of [AWS Systems Manager Parameter Store](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html) parameters instead of the keys themselves. Each parameter holds one key as it would be written for `encryption_key`, preferably as a `SecureString`. As with `encryption_key`, the first one encrypts and the rest are old keys:

```caddyfile
encryption_key_ssm "/caddy/cert-encryption-key-2026-11" "/caddy/cert-encryption-key"
```

Creating one:

```sh
aws ssm put-parameter --type SecureString --name /caddy/cert-encryption-key \
  --value "base64:$(openssl rand -base64 32)"
```

A version or label of a single parameter works as well, which makes rotation a matter of writing a new version:

```caddyfile
encryption_key_ssm "/caddy/cert-encryption-key:2" "/caddy/cert-encryption-key:1"
```

- The parameters are read with the region and credentials configured for the bucket (`region`, `access_key`/`secret_key`, `profile`, `role_arn`, or the default chain). A parameter given by ARN is read from the region in its ARN.
- The identity Caddy runs as needs `ssm:GetParameter` on the parameters, and `kms:Decrypt` on the KMS key if the SecureString uses a customer managed key.
- The parameters are read once, when Caddy starts or reloads its config. Reload Caddy after changing a parameter.
- `encryption_key_ssm` cannot be combined with `encryption_key` or `encryption_key_file`.
- `endpoint` and `insecure` do not apply here: the keys are always read from AWS, over a verified connection.

## What is an S3-compatible service?

The service must support:

- v4 signatures
- GetObject, PutObject, DeleteObject, HeadObject and ListObjectsV2
- conditional writes on PutObject (`If-None-Match: *` and `If-Match`), which the cross-instance lock and the re-encryption of objects under an old key rely on

## Development

```sh
make test       # go test ./...
make test-race  # with the race detector
make lint       # golangci-lint v2
make fmt        # gofumpt
```

CI runs the tests with the race detector on the two current Go releases, and the linter, on every push and pull request. There is nothing to build or release: the plugin is compiled into Caddy by `xcaddy`.

## Credits & thanks

caddycertkeeper stands on other people's work, and it would not exist without them:

- [@techknowlogick](https://github.com/techknowlogick), who maintained [certmagic-s3](https://github.com/techknowlogick/certmagic-s3) for years, moved it to the AWS SDK and kept it working across many Caddy and CertMagic releases. This fork starts from certmagic-s3 at commit [`6c26852`](https://github.com/techknowlogick/certmagic-s3/commit/6c26852) (October 2026), with all of that history behind it.
- [@thomersch](https://github.com/thomersch), who wrote the original [Certmagic Storage Backend for Generic S3 Providers](https://github.com/thomersch/certmagic-generic-s3), including the client-side encryption this plugin still uses.
- Everyone who reported bugs and sent fixes to both projects, among them the people behind the storage-clean fix and the rewrite of the cross-instance lock.

Thank you. The fork exists only to ship fixes faster, not because anything was wrong with the work it builds on.

## License

[Apache 2.0](LICENSE), the same as the projects it is forked from. The changes made in this fork are listed under [What is fixed and added here](#what-is-fixed-and-added-here).
