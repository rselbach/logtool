package util

import (
    "crypto/sha256"
    "encoding/hex"
)

type Hasher struct{ salt string }

func NewHasher(salt string) *Hasher { return &Hasher{salt: salt} }

func (h *Hasher) HashString(s string) string {
    sum := sha256.Sum256([]byte(h.salt + ":" + s))
    return hex.EncodeToString(sum[:])
}

