package main

import (
	"fmt"
	"githubmcom/eternal-flame-AD/keepass-vault-sync/model"
	"githubmcom/eternal-flame-AD/keepass-vault-sync/util"
	"log"
	"os"

	"github.com/tobischo/gokeepasslib"
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

func countKeepassGroup(path []string, group *gokeepasslib.Group) uint64 {
	var count uint64
	for _, entry := range group.Entries {
		if _, err := model.EntryFromKeepass(path, &entry); err != nil {
			log.Printf("failed to process entry: %v", err)
		} else {
			count++
		}
	}
	for _, subgroup := range group.Groups {
		count += countKeepassGroup(append(path, subgroup.Name), &subgroup)
	}
	return count
}
