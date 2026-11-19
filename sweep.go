package caddycertkeeper

import (
	"context"
	"strings"
	"time"

	"go.uber.org/zap"
)

// sweepAttempts is how many times the sweep reads an object that another
// instance keeps changing under it before it gives up on knowing its key.
const sweepAttempts = 3

// sweepDelay is how long after provisioning the sweep starts. A config that
// is only validated, or that fails to start, is normally unloaded well
// within it, and then writes nothing to the bucket. It also lets Caddy load
// its certificates first, which re-encrypts those.
var sweepDelay = 10 * time.Second

// sweepAfter runs the sweep once delay has passed, unless ctx, the config's
// context, is done by then.
func (s3 *S3) sweepAfter(ctx context.Context, delay time.Duration) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(delay):
	}
	s3.sweep(ctx)
}

// sweep reads every object in the storage once, which re-encrypts the ones
// still under an old key, and logs what it found.
//
// Reading as Caddy goes is not enough to retire an old key. CertMagic loads
// the ACME account only when it issues or renews a certificate, and never
// loads what belongs to a site that is no longer configured, so those would
// stay under the old key for weeks. The summary logged at the end is what
// says the old keys are needed for nothing.
//
// It is safe next to anything else using the bucket, this instance
// included: every rewrite is conditional on the version that was read.
func (s3 *S3) sweep(ctx context.Context) {
	start := time.Now()
	s3.Logger.Info("re-encryption sweep started: old encryption keys are configured")

	var checked, rewrote, left, unreadable int
	// stopped reports, and logs, that the config was unloaded under the
	// sweep. What failed because of that is not a finding.
	stopped := func() bool {
		if ctx.Err() == nil {
			return false
		}
		s3.Logger.Info("re-encryption sweep stopped before it finished", zap.Int("objects", checked))
		return true
	}

	keys, err := s3.List(ctx, "", true)
	if stopped() {
		return
	}
	if err != nil {
		s3.Logger.Warn("re-encryption sweep failed: listing the storage", zap.Error(err))
		return
	}

	for _, key := range keys {
		// A lock is not an encrypted object, and not one to rewrite.
		if strings.HasSuffix(key, lockSuffix) {
			continue
		}

		// The listing has every name under the prefix, and the storage
		// cannot ask for one that starts with a slash: it would get the
		// object named without it.
		if strings.HasPrefix(key, "/") {
			checked++
			unreadable++
			s3.Logger.Warn("re-encryption sweep found an object the storage cannot address",
				zap.String("key", s3.objDirName("")+key),
			)
			continue
		}

		state, err := s3.settle(ctx, key)
		if stopped() {
			return
		}
		switch {
		case state == gone:
			// Removed since the listing. Only that: another error that
			// reads as "does not exist" is not a missing object.
			continue
		case err != nil:
			unreadable++
			s3.Logger.Warn("re-encryption sweep could not read an object",
				zap.String("key", s3.objName(key)),
				zap.Error(err),
			)
		case state == rewritten:
			rewrote++
		case state != underCurrentKey:
			left++
			s3.Logger.Warn("re-encryption sweep left an object under an old encryption key",
				zap.String("key", s3.objName(key)),
			)
		}
		checked++
	}

	log := s3.Logger.Info
	if left > 0 || unreadable > 0 {
		log = s3.Logger.Warn
	}
	log("re-encryption sweep finished",
		zap.Int("objects", checked),
		zap.Int("rewritten", rewrote),
		zap.Int("left_under_old_keys", left),
		zap.Int("unreadable", unreadable),
		zap.Duration("duration", time.Since(start)),
	)
}

// settle reads the object at key until it knows which key the object is
// under: when another instance replaced the object between the read and the
// rewrite, it is that instance's version that has to be looked at.
func (s3 *S3) settle(ctx context.Context, key string) (state keyState, err error) {
	for range sweepAttempts {
		if _, state, err = s3.read(ctx, key); err != nil || state != changedSinceRead {
			break
		}
	}
	return state, err
}
