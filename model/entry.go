package model

import (
	"githubmcom/eternal-flame-AD/keepass-vault-sync/util"
	"strings"

	"github.com/google/uuid"
	"github.com/tobischo/gokeepasslib"
)

type UniversalEntry struct {
	UUID uuid.UUID

	Path []string
	Name string

	Username string
	Password string

	Tags []string

	KV map[string]string
}

func (e UniversalEntry) HasTag(tag string) bool {
	return util.Contain(e.Tags, tag)
}

func (e UniversalEntry) VaultKV1() (path string, kv map[string]interface{}) {
	path = ""
	for _, p := range e.Path {
		p = util.VaultPathEscape(p)
		path += p + "/"
	}
	path = strings.TrimSuffix(path, "/")
	pathUnescaped := strings.Join(e.Path, "/")

	kv = make(map[string]interface{})
	kv["username"] = e.Username
	kv["password"] = e.Password
	kv["keepass_uuid"] = e.UUID.String()
	if pathUnescaped != path {
		kv["keepass_path"] = pathUnescaped
	}
	if len(e.Tags) > 0 {
		kv["keepass_tags"] = strings.Join(e.Tags, ",")
	}

	for k, v := range e.KV {
		kv[k] = v
	}
	return path + "/" + util.VaultPathEscape(e.Name), kv
}

func EntryFromKeepass(groupPath []string, entry *gokeepasslib.Entry) (*UniversalEntry, error) {
	uuid := (uuid.UUID)(entry.UUID)
	title := entry.GetTitle()
	password := entry.GetPassword()

	kvOut := make(map[string]string)
	for _, kv := range entry.Values {
		kvOut[kv.Key] = kv.Value.Content
	}

	username := kvOut["UserName"]
	delete(kvOut, "UserName")
	delete(kvOut, "Password")
	delete(kvOut, "Title")

	return &UniversalEntry{
		UUID: uuid,

		Path: groupPath,
		Name: title,

		Username: username,
		Password: password,

		Tags: strings.Split(entry.Tags, ","),

		KV: kvOut,
	}, nil
}
