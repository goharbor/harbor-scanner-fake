package scanner

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"
	"github.com/heww/harbor-scanner-fake/api"
	"github.com/heww/harbor-scanner-fake/pkg/util"
)

func makeResolver(u *url.URL) remotes.Resolver {
	var transport http.RoundTripper
	if true {
		transport = util.NewInsecureTransport()
	} else {
		transport = util.NewDefaultTransport()
	}

	client := &http.Client{Transport: transport}

	authorizer := docker.NewAuthorizer(client, func(host string) (string, string, error) {
		if host == u.Host && u.User != nil {
			password, _ := u.User.Password()

			return u.User.Username(), password, nil
		}

		return "", "", nil
	})

	plainHTTP := func(host string) (bool, error) {
		if host == u.Host {
			return strings.ToLower(u.Scheme) == "http", nil
		}

		return false, nil // default is https
	}

	return docker.NewResolver(docker.ResolverOptions{
		Hosts: docker.ConfigureDefaultRegistries(
			docker.WithAuthorizer(authorizer),
			docker.WithClient(client),
			docker.WithPlainHTTP(plainHTTP),
		),
	})
}

func parseBasicAuth(header string) (string, string, bool) {
	s := strings.SplitN(header, " ", 2)
	if len(s) != 2 {
		return "", "", false
	}

	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return "", "", false
	}

	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return "", "", false
	}

	return pair[0], pair[1], true
}

func mustGetArtifact(req *api.ScanRequest) string {
	u, err := url.Parse(*req.Registry.Url)
	if err != nil {
		log.Fatal(err)
	}

	return fmt.Sprintf("%s/%s@%s", u.Host, *req.Artifact.Repository, *req.Artifact.Digest)
}
