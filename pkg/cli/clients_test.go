package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockClientDatastore struct {
	mock.Mock
	hubauth.DataStore
}

func (m *mockClientDatastore) CreateClient(ctx context.Context, client *hubauth.Client) (string, error) {
	args := m.Called(ctx, client)
	return args.String(0), args.Error(1)
}
func (m *mockClientDatastore) ListClients(ctx context.Context) ([]*hubauth.Client, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*hubauth.Client), args.Error(1)
}
func (m *mockClientDatastore) DeleteClient(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *mockClientDatastore) MutateClient(ctx context.Context, id string, mut []*hubauth.ClientMutation) error {
	args := m.Called(ctx, id, mut)
	return args.Error(0)
}

func TestClientsListCmd(t *testing.T) {
	cmd := clientsListCmd{}
	cfg := &Config{DB: &mockClientDatastore{}}

	createTime := time.Now().Add(-5 * time.Second)
	updateTime := time.Now()

	clients := []*hubauth.Client{
		{
			ID:                 "client1",
			RedirectURIs:       []string{"redirect1", "redirect2"},
			RefreshTokenExpiry: 60 * time.Second,
			CreateTime:         createTime,
			UpdateTime:         updateTime,
		},
		{
			ID:                 "client2",
			RedirectURIs:       []string{},
			RefreshTokenExpiry: 5 * time.Second,
			CreateTime:         createTime,
			UpdateTime:         updateTime,
		},
	}

	cfg.DB.(*mockClientDatastore).On("ListClients", mock.Anything).Return(clients, nil)

	r, w, err := os.Pipe()
	require.NoError(t, err)
	origStdout := os.Stdout
	os.Stdout = w

	require.NoError(t, cmd.Run(cfg))

	os.Stdout = origStdout
	buf := make([]byte, 2048)
	n, err := r.Read(buf)
	require.NoError(t, err)

	expectedBuf := new(bytes.Buffer)
	tw := table.NewWriter()
	tw.SetOutputMirror(expectedBuf)
	tw.AppendHeader(table.Row{"ID", "RedirectURIs", "RefreshTokenExpiry", "CreateTime", "UpdateTime"})
	for _, c := range clients {
		tw.AppendRow(table.Row{c.ID, c.RedirectURIs, c.RefreshTokenExpiry, c.CreateTime, c.UpdateTime})
	}
	tw.Render()

	require.Equal(t, expectedBuf.String(), string(buf[:n]))
}

func TestClientsListErrors(t *testing.T) {
	testCases := []struct {
		Desc           string
		ListClientsErr error
		ExpectedErr    error
	}{
		{
			Desc:           "fail to list clients",
			ListClientsErr: errors.New("list clients error"),
			ExpectedErr:    errors.New("list clients error"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			cmd := clientsListCmd{}
			cfg := &Config{DB: &mockClientDatastore{}}
			cfg.DB.(*mockClientDatastore).On("ListClients", mock.Anything).Return([]*hubauth.Client{}, testCase.ListClientsErr)

			err := cmd.Run(cfg)
			if testCase.ExpectedErr != nil {
				require.Equal(t, testCase.ExpectedErr, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestClientCreateCmd(t *testing.T) {
	cmd := clientsCreateCmd{
		RedirectURIs:       []string{"redirect1", "redirect2"},
		RefreshTokenExpiry: 60,
	}
	cfg := &Config{DB: &mockClientDatastore{}}

	expectedClient := &hubauth.Client{
		RedirectURIs:       cmd.RedirectURIs,
		RefreshTokenExpiry: time.Duration(cmd.RefreshTokenExpiry) * time.Second,
	}
	expectedClientID := "createdClientID"

	cfg.DB.(*mockClientDatastore).On("CreateClient", mock.Anything, expectedClient).Return(expectedClientID, nil)

	r, w, err := os.Pipe()
	require.NoError(t, err)
	origStdout := os.Stdout
	os.Stdout = w

	require.NoError(t, cmd.Run(cfg))

	os.Stdout = origStdout
	buf := make([]byte, 2048)
	n, err := r.Read(buf)
	require.NoError(t, err)

	require.Equal(t, fmt.Sprintf("%s\n", expectedClientID), string(buf[:n]))
}

func TestClientCreateErrors(t *testing.T) {
	testCases := []struct {
		Desc             string
		CreateClientsErr error
		ExpectedErr      error
	}{
		{
			Desc:             "fail to create client",
			CreateClientsErr: errors.New("create client error"),
			ExpectedErr:      errors.New("create client error"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			cmd := clientsCreateCmd{}
			cfg := &Config{DB: &mockClientDatastore{}}
			cfg.DB.(*mockClientDatastore).On("CreateClient", mock.Anything, mock.Anything).Return("", testCase.CreateClientsErr)

			err := cmd.Run(cfg)
			if testCase.ExpectedErr != nil {
				require.Equal(t, testCase.ExpectedErr, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestClientDeleteCmd(t *testing.T) {
	cmd := clientsDeleteCmd{
		ClientID: "clientID",
	}
	cfg := &Config{DB: &mockClientDatastore{}}

	cfg.DB.(*mockClientDatastore).On("DeleteClient", mock.Anything, cmd.ClientID).Return(nil)

	require.NoError(t, cmd.Run(cfg))
}

func TestClientDeleteErrors(t *testing.T) {
	cmd := clientsDeleteCmd{
		ClientID: "clientID",
	}
	cfg := &Config{DB: &mockClientDatastore{}}

	expectedError := errors.New("delete client error")
	cfg.DB.(*mockClientDatastore).On("DeleteClient", mock.Anything, mock.Anything).Return(expectedError)

	require.Equal(t, expectedError, cmd.Run(cfg))
}

func TestClientUpdateCmd(t *testing.T) {
	t.Run("empty mutations", func(t *testing.T) {
		cmd := clientUpdateCmd{
			ClientID: "clientID",
		}
		cfg := &Config{DB: &mockClientDatastore{}}
		var expectedMutations []*hubauth.ClientMutation
		cfg.DB.(*mockClientDatastore).On("MutateClient", mock.Anything, "clientID", expectedMutations).Return(nil)
		require.Equal(t, nil, cmd.Run(cfg))
	})
	t.Run("set refresh token expiry", func(t *testing.T) {
		cmd := clientUpdateCmd{
			ClientID:           "clientID",
			RefreshTokenExpiry: 300,
		}
		cfg := &Config{DB: &mockClientDatastore{}}
		expectedMutations := []*hubauth.ClientMutation{
			&hubauth.ClientMutation{
				Op:                 hubauth.ClientMutationOpSetRefreshTokenExpiry,
				RefreshTokenExpiry: 5 * time.Minute,
			},
		}
		cfg.DB.(*mockClientDatastore).On("MutateClient", mock.Anything, "clientID", expectedMutations).Return(nil)
		require.Equal(t, nil, cmd.Run(cfg))
	})
	t.Run("multiple mutations", func(t *testing.T) {
		cmd := clientUpdateCmd{
			ClientID:           "clientID",
			RefreshTokenExpiry: 300,
			AddRedirectURIs:    []string{"http://localhost:1234", "http://localhost:5678"},
			DeleteRedirectURIs: []string{"http://removed-domain:1234"},
		}
		cfg := &Config{DB: &mockClientDatastore{}}
		expectedMutations := []*hubauth.ClientMutation{
			&hubauth.ClientMutation{
				Op:                 hubauth.ClientMutationOpSetRefreshTokenExpiry,
				RefreshTokenExpiry: 5 * time.Minute,
			},
			&hubauth.ClientMutation{
				Op:          hubauth.ClientMutationOpAddRedirectURI,
				RedirectURI: "http://localhost:1234",
			},
			&hubauth.ClientMutation{
				Op:          hubauth.ClientMutationOpAddRedirectURI,
				RedirectURI: "http://localhost:5678",
			},
			&hubauth.ClientMutation{
				Op:          hubauth.ClientMutationOpDeleteRedirectURI,
				RedirectURI: "http://removed-domain:1234",
			},
		}
		cfg.DB.(*mockClientDatastore).On("MutateClient", mock.Anything, "clientID", expectedMutations).Return(nil)
		require.Equal(t, nil, cmd.Run(cfg))
	})
}
