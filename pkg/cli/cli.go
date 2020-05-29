package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/jedib0t/go-pretty/v6/table"
)

type Config struct {
	DB hubauth.DataStore
}

var CLI struct {
	Clients clientsCmd `kong:"cmd,help='manage oauth clients'"`
}

type clientsCmd struct {
	List   clientsListCmd   `kong:"cmd,help='list clients',default:'1'"`
	Create clientsCreateCmd `kong:"cmd,help='create client'"`
}

type clientsListCmd struct {
}

func (c *clientsListCmd) Run(cfg *Config) error {
	clients, err := cfg.DB.ListClients(context.Background())
	if err != nil {
		return nil
	}
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"ID", "RedirectURIs", "RefreshTokenExpiry", "CreateTime", "UpdateTime"})
	for _, c := range clients {
		t.AppendRow(table.Row{c.ID, c.RedirectURIs, c.RefreshTokenExpiry, c.CreateTime, c.UpdateTime})
	}
	t.Render()
	return nil
}

type clientsCreateCmd struct {
	RedirectURIs       []string `kong:"required,name='redirect-uris',help='comma-separated redirect URIs'"`
	RefreshTokenExpiry int      `kong:"name='refresh-token-expiry',default='86400',help='refresh token expiry, in seconds'"`
}

func (cmd *clientsCreateCmd) Run(cfg *Config) error {
	c := &hubauth.Client{
		RedirectURIs:       cmd.RedirectURIs,
		RefreshTokenExpiry: time.Duration(cmd.RefreshTokenExpiry) * time.Second,
	}
	id, err := cfg.DB.CreateClient(context.Background(), c)
	if err != nil {
		return err
	}
	fmt.Println(id)
	return nil
}
