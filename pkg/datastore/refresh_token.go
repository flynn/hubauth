package datastore

import (
	"context"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/flynn/hubauth/pkg/hubauth"
	"go.opencensus.io/trace"
	"golang.org/x/exp/errors/fmt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func buildRefreshToken(t *hubauth.RefreshToken) (*refreshToken, error) {
	code, err := codeKey(t.CodeID)
	if err != nil {
		return nil, err
	}

	var key *datastore.Key
	if t.ID == "" {
		parentKey, err := clientKey(t.ClientID)
		if err != nil {
			return nil, err
		}
		key = datastore.IncompleteKey(kindRefreshToken, parentKey)
	} else {
		var err error
		key, err = refreshTokenKey(t.ID)
		if err != nil {
			return nil, err
		}
		clientID := key.Parent.Encode()
		if clientID != t.ClientID {
			return nil, fmt.Errorf("datastore: refresh token key client ID doesn't match (%q != %q)", clientID, t.ClientID)
		}
	}

	var now time.Time
	if !t.IssueTime.IsZero() {
		now = t.IssueTime
	} else {
		now = time.Now()
	}
	return &refreshToken{
		Key:         key,
		UserID:      t.UserID,
		UserEmail:   t.UserEmail,
		RedirectURI: t.RedirectURI,
		Code:        code,
		CreateTime:  now,
		IssueTime:   now,
		ExpiryTime:  t.ExpiryTime,
	}, nil
}

type refreshToken struct {
	Key         *datastore.Key `datastore:"__key__"`
	UserID      string
	UserEmail   string
	RedirectURI string
	Code        *datastore.Key
	CreateTime  time.Time
	IssueTime   time.Time
	ExpiryTime  time.Time
}

func (t *refreshToken) Export() *hubauth.RefreshToken {
	return &hubauth.RefreshToken{
		ID:          t.Key.Encode(),
		ClientID:    t.Key.Parent.Encode(),
		UserID:      t.UserID,
		UserEmail:   t.UserEmail,
		RedirectURI: t.RedirectURI,
		CodeID:      t.Code.Encode(),
		CreateTime:  t.CreateTime,
		IssueTime:   t.IssueTime,
		ExpiryTime:  t.ExpiryTime,
	}
}

func refreshTokenKey(id string) (*datastore.Key, error) {
	k, err := datastore.DecodeKey(id)
	if err != nil {
		return nil, hubauth.ErrNotFound
	}
	if k.Kind != kindRefreshToken {
		return nil, hubauth.ErrNotFound
	}
	if k.Parent == nil || k.Parent.Kind != kindClient {
		return nil, hubauth.ErrNotFound
	}
	return k, nil
}

func (s *service) GetRefreshToken(ctx context.Context, id string) (*hubauth.RefreshToken, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.GetRefreshToken")
	span.AddAttributes(trace.StringAttribute("refresh_token_id", id))
	defer span.End()

	k, err := refreshTokenKey(id)
	if err != nil {
		return nil, err
	}
	res := &refreshToken{}
	if err := s.db.Get(ctx, k, res); err != nil {
		if err == datastore.ErrNoSuchEntity {
			err = hubauth.ErrNotFound
		}
		return nil, fmt.Errorf("datastore: error fetching refresh token %s: %w", id, err)
	}
	return res.Export(), nil
}

func (s *service) AllocateRefreshTokenID(ctx context.Context, clientID string) (string, error) {
	parentKey, err := clientKey(clientID)
	if err != nil {
		return "", err
	}
	return datastore.NameKey(kindRefreshToken, newRandomID(), parentKey).Encode(), nil
}

func (s *service) CreateRefreshToken(ctx context.Context, token *hubauth.RefreshToken) (string, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.CreateRefreshToken")
	defer span.End()

	data, err := buildRefreshToken(token)
	if err != nil {
		return "", err
	}
	key, err := s.db.Put(ctx, data.Key, data)
	if err != nil {
		return "", fmt.Errorf("datastore: error creating refresh token: %w", err)
	}
	id := key.Encode()
	span.AddAttributes(trace.StringAttribute("refresh_token_id", id))
	return id, nil
}

func (s *service) RenewRefreshToken(ctx context.Context, clientID, id string, prevIssueTime, now time.Time) (*hubauth.RefreshToken, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.RenewRefreshToken")
	span.AddAttributes(
		trace.StringAttribute("refresh_token_id", id),
		trace.StringAttribute("client_id", id),
		trace.StringAttribute("refresh_token_issue_time", prevIssueTime.String()),
	)
	defer span.End()

	k, err := refreshTokenKey(id)
	if err != nil {
		return nil, err
	}
	t := &refreshToken{}
	if err := s.db.Get(ctx, k, t); err != nil {
		if err == datastore.ErrNoSuchEntity {
			err = hubauth.ErrNotFound
		}
		return nil, err
	}
	now = now.Truncate(time.Millisecond)
	if now.After(t.ExpiryTime) {
		return nil, hubauth.ErrExpired
	}

	if clientID != t.Key.Parent.Encode() {
		err = hubauth.ErrClientIDMismatch
	} else if !t.IssueTime.Truncate(time.Millisecond).Equal(prevIssueTime.Truncate(time.Millisecond)) {
		err = hubauth.ErrRefreshTokenVersionMismatch
	}
	if err != nil {
		if dErr := s.db.Delete(ctx, k); dErr != nil {
			return nil, fmt.Errorf("datastore: error deleting refresh token %s after failed renewal: %w", id, dErr)
		}
		return nil, fmt.Errorf("datastore: error renewing refresh token %s: %w", id, err)
	}
	t.IssueTime = now
	_, err = s.db.Mutate(ctx, datastore.NewUpdate(k, t))
	if err != nil {
		if status.Code(err) == codes.NotFound {
			err = hubauth.ErrNotFound
		}
		return nil, fmt.Errorf("datastore: error renewing refresh token %s: %w", id, err)
	}
	return t.Export(), nil
}

func (s *service) DeleteRefreshToken(ctx context.Context, id string) error {
	ctx, span := trace.StartSpan(ctx, "datastore.DeleteRefreshToken")
	span.AddAttributes(trace.StringAttribute("refresh_token_id", id))
	defer span.End()

	k, err := refreshTokenKey(id)
	if err != nil {
		return err
	}
	if err := s.db.Delete(ctx, k); err != nil {
		return fmt.Errorf("datastore: error deleting refresh token %s: %w", id, err)
	}
	return nil
}

func (s *service) DeleteRefreshTokensWithCode(ctx context.Context, c string) ([]string, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.DeleteRefreshTokensWithCode")
	span.AddAttributes(trace.StringAttribute("code_id", c))
	defer span.End()

	parsedCodeKey, err := codeKey(c)
	if err != nil {
		return nil, err
	}
	q := datastore.NewQuery(kindRefreshToken).Filter("Code = ", parsedCodeKey).KeysOnly()
	keys, err := s.db.GetAll(ctx, q, nil)
	if err != nil {
		return nil, fmt.Errorf("datastore: error listing refresh tokens with code %s: %w", c, err)
	}
	if len(keys) == 0 {
		return nil, nil
	}
	if err := s.db.DeleteMulti(ctx, keys); err != nil {
		return nil, fmt.Errorf("datastore: error deleting refresh tokens with code %s: %w", c, err)
	}
	res := make([]string, len(keys))
	for i, k := range keys {
		res[i] = k.Encode()
	}
	span.AddAttributes(trace.Int64Attribute("refresh_tokens_deleted", int64(len(res))))
	return res, nil
}

func (s *service) DeleteExpiredRefreshTokens(ctx context.Context) ([]string, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.DeleteExpiredRefreshTokens")
	defer span.End()

	res, err := s.deleteExpired(ctx, kindRefreshToken)
	span.AddAttributes(trace.Int64Attribute("refresh_tokens_deleted", int64(len(res))))

	return res, err
}
