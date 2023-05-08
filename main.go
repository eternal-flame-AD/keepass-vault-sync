package main

import (
	"context"
	"flag"
	"fmt"
	"githubmcom/eternal-flame-AD/keepass-vault-sync/model"
	"githubmcom/eternal-flame-AD/keepass-vault-sync/util"
	"io"
	"log"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

var (
	flagKeepassFile        = flag.String("input", "example.kdbx", "Path to keepass file")
	flagSecretMount        = flag.String("mount", "password", "Vault secret mount path")
	flagFilterTag          = flag.String("tag", "", "Filter entries by tag")
	flagFilterPath         util.ListVar
	flagFilterPathCompiled []*regexp.Regexp

	flagDelete  = flag.Bool("delete", false, "Delete entries that are not in keepass")
	flagTimeout = flag.Duration("timeout", time.Second*5, "Timeout for vault operations")
	flagVerbose = flag.Bool("v", false, "Verbose output")
)

func init() {
	flag.Var(&flagFilterPath, "exclude-path", "Exclude entries by path regexp")
}

func compileRegexpFlags() error {
	for _, pattern := range flagFilterPath {
		if re, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("failed to compile regexp %q: %w", pattern, err)
		} else {
			flagFilterPathCompiled = append(flagFilterPathCompiled, re)
		}
	}
	return nil
}

func timeoutContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), *flagTimeout)
}

// GetVaultToken retrieves the vault token from the env variable VAULT_TOKEN or from ~/.vault-token
func GetVaultToken() string {
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		return token
	}
	home, err := os.UserHomeDir()
	if err != nil {
		log.Printf("failed to get user home directory: %v", err)
	} else {
		tokenFilePath := path.Join(home, ".vault-token")
		tokenFile, err := os.Open(tokenFilePath)
		if err != nil {
			log.Printf("failed to open vault token file: %v", err)
		} else {
			defer tokenFile.Close()
			tokenBytes, err := io.ReadAll(tokenFile)
			if err != nil {
				log.Printf("failed to read vault token file: %v", err)
			}
			if token := strings.TrimSpace(string(tokenBytes)); token != "" {
				return token
			}
		}
	}

	token, err := util.AskPass("Vault token: ")
	if err != nil {
		log.Fatalf("failed to read vault token: %v", err)
	}
	return string(token)
}

func main() {
	flag.Parse()
	compileRegexpFlags()

	if *flagKeepassFile == "" {
		flag.Usage()
		return
	}

	// log into vault amd get kv client
	vaultClient, err := vault.NewClient(vault.DefaultConfig())
	if err != nil {
		log.Fatalf("failed to create vault client: %v", err)
	}
	if vaultClient.Token() == "" {
		vaultClient.SetToken(GetVaultToken())
	}
	vaultKv := vaultClient.KVv1(*flagSecretMount)

	// figure out which paths already exist on Vault
	existingPaths, err := PathsFromKVv1(timeoutContext, vaultClient.Logical(), vaultKv, *flagSecretMount)
	if err != nil {
		log.Fatalf("failed to read vault paths: %v", err)
	}
	log.Printf("found %d existing secrets", len(existingPaths))

	existingPathsStillExist := make(map[string]bool)
	for _, path := range existingPaths {
		existingPathsStillExist[path] = false
	}

	// start reading keepass file
	root, err := readKeepassDB(*flagKeepassFile)
	if err != nil {
		log.Fatalf("failed to read keepass file: %v", err)
	}
	countKeepassEntries := countKeepassGroup(nil, &root.Groups[0])
	entries := make(chan model.UniversalEntry)
	go func() {
		processKeepassGroup(nil, &root.Groups[0], entries)
		close(entries)
	}()

	var counts struct {
		StillExist    uint64
		NoLongerExist uint64
		New           uint64
		Filtered      uint64
	}

	// start progress display
	progressCtx, progressCancel := context.WithCancel(context.Background())
	progressIncrement := StartProgress(progressCtx, 2*time.Second, countKeepassEntries)
	// start submitting entries to vault
loopEntries:
	for entry := range entries {
		if *flagVerbose {
			fmt.Printf("%v\n", entry)
		}

		if *flagFilterTag != "" && !entry.HasTag(*flagFilterTag) {
			if *flagVerbose {
				log.Printf("skipping secret %s due to missing tag", entry.Name)
			}
			counts.Filtered++
			progressIncrement(1)
			continue loopEntries
		}

		path, value := entry.VaultKV1()

		for _, re := range flagFilterPathCompiled {
			if re.MatchString(path) {
				if *flagVerbose {
					log.Printf("skipping secret %s due to matching exclude-path", entry.Name)
				}
				counts.Filtered++
				progressIncrement(1)
				continue loopEntries
			}
		}

		if p, ok := existingPathsStillExist[path]; !p && ok {
			existingPathsStillExist[path] = true
		} else if !ok {
			counts.New++
		}

		retries := 3
		for retries > 0 {
			putCtx, putCancel := timeoutContext()
			if err := vaultKv.Put(putCtx, path, value); err != nil {
				if *flagVerbose || retries == 1 {
					log.Printf("[retry %d/3] failed to put secret %s: %v", 4-retries, entry.Name, err)
				}
				putCancel()
				retries--
				continue
			}
			putCancel()
			break
		}

		progressIncrement(1)
	}
	progressCancel()

	for path, exists := range existingPathsStillExist {
		if exists {
			counts.StillExist++
		} else {
			counts.NoLongerExist++
			if *flagDelete {
				log.Printf("deleting secret %s", path)
				ctx, cancel := timeoutContext()
				if err := vaultKv.Delete(ctx, path); err != nil {
					log.Printf("failed to delete secret %s: %v", path, err)
				}
				cancel()
			}
		}
	}

	noLongerExistPrompt := "no longer exist"
	if *flagDelete {
		noLongerExistPrompt = "deleted"
	}
	log.Printf("Totals: %d still exist, %d %s, %d new, %d filtered",
		counts.StillExist, counts.NoLongerExist, noLongerExistPrompt,
		counts.New, counts.Filtered)
}
