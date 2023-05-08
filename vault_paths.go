package main

import (
	"context"
	"fmt"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

func PathsFromKVv1(ctxFactory func() (context.Context, context.CancelFunc), logical *vault.Logical, kv *vault.KVv1, mount string) (paths []string, err error) {
	mount = strings.TrimSuffix(mount, "/")
	dfsFolders := []string{mount}
	for len(dfsFolders) > 0 {
		this := dfsFolders[0]
		dfsFolders = dfsFolders[1:]

		ctx, cancel := ctxFactory()
		keys, err := logical.ListWithContext(ctx, this)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("error listing %s: %w", this, err)
		}
		cancel()

		for _, keys := range keys.Data {
			keys := keys.([]any)
			for _, key := range keys {
				key := key.(string)
				if strings.HasSuffix(key, "/") {
					dfsFolders = append(dfsFolders, this+"/"+key[:len(key)-1])
				} else {
					paths = append(paths, this+"/"+key)
				}
			}
		}
	}
	for i := range paths {
		paths[i] = strings.TrimPrefix(paths[i], mount+"/")
	}

	return
}
