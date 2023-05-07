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
	"strings"

	"github.com/tobischo/gokeepasslib"

	vault "github.com/hashicorp/vault/api"
)

var (
	flagKeepassFile = flag.String("input", "example.kdbx", "Path to keepass file")
	flagSecretMount = flag.String("mount", "password", "Vault secret mount path")
	flagFilterTag   = flag.String("tag", "", "Filter entries by tag")
	flagVerbose     = flag.Bool("v", false, "Verbose output")
)

func readKeepassDB(filename string) (*gokeepasslib.RootData, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open keepass file: %w", err)
	}
	defer f.Close()

	db := gokeepasslib.NewDatabase()
	creds, err := util.AskPass("Password: ")
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	db.Credentials = gokeepasslib.NewPasswordCredentials(string(creds))

	dec := gokeepasslib.NewDecoder(f)
	if err != nil {
		return nil, fmt.Errorf("failed to create decoder: %w", err)
	}
	if err := dec.Decode(db); err != nil {
		return nil, fmt.Errorf("failed to decode keepass file: %w", err)
	}

	if err := db.UnlockProtectedEntries(); err != nil {
		return nil, fmt.Errorf("failed to unlock protected entries: %w", err)
	}

	return db.Content.Root, nil
}

func processKeepassGroup(path []string, group *gokeepasslib.Group, collectedEntries chan<- model.UniversalEntry) {
	for _, entry := range group.Entries {
		if entry, err := model.EntryFromKeepass(path, &entry); err != nil {
			log.Printf("failed to process entry: %v", err)
		} else {
			collectedEntries <- *entry
		}
	}
	for _, subgroup := range group.Groups {
		processKeepassGroup(append(path, subgroup.Name), &subgroup, collectedEntries)
	}
}

func getVaultToken() string {
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

	if *flagKeepassFile == "" {
		flag.Usage()
		return
	}

	vaultClient, err := vault.NewClient(vault.DefaultConfig())
	if err != nil {
		log.Fatalf("failed to create vault client: %v", err)
	}
	if vaultClient.Token() == "" {
		vaultClient.SetToken(getVaultToken())
	}
	vaultKv := vaultClient.KVv1(*flagSecretMount)

	root, err := readKeepassDB(*flagKeepassFile)
	if err != nil {
		log.Fatalf("failed to read keepass file: %v", err)
	}
	entries := make(chan model.UniversalEntry)
	go func() {
		processKeepassGroup([]string{}, &root.Groups[0], entries)
		close(entries)
	}()

	putCtx := context.Background()
	for entry := range entries {
		if *flagVerbose {
			fmt.Printf("%v\n", entry)
		}
		path, value := entry.VaultKV1()
		if *flagFilterTag != "" && !entry.HasTag(*flagFilterTag) {
			if *flagVerbose {
				log.Printf("skipping secret %s due to missing tag", entry.Name)
			}
			continue
		}
		if err := vaultKv.Put(putCtx, path, value); err != nil {
			log.Printf("failed to put secret %s: %v", entry.Name, err)
		}
	}
}
