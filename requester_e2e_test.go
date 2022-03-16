// +build e2e

package core

import (
	"github.com/stretchr/testify/suite"
	"testing"
)

type RequesterE2ETestSuite struct {
	suite.Suite
}

func TestRequesterE2ETestSuite(t *testing.T) {
	suite.Run(t, new(RequesterE2ETestSuite))
}

func (r *RequesterE2ETestSuite) TestRequest_RequesterToStructPagination_ExpectSuccess() {
	ctx := NewContext(&ContextOptions{
		ENV: NewEnv(),
	})

	items := make([]interface{}, 0)
	pageResponse, ierr := RequesterToStructPagination(items, &PageOptions{
		Q:       "singh",
		OrderBy: []string{"created_at"},
	}, func() (*RequestResponse, error) {
		return ctx.Requester().Get("/vc/schema", &RequesterOptions{
			BaseURL: "https://etda-ssi.finema.dev",
			Params: map[string][]string{
				"q":        {"singh"},
				"order_by": {"created_at"},
			},
		})
	})

	r.NoError(ierr)
	r.NotNil(pageResponse)
	r.Equal("singh", pageResponse.Q)
	r.Equal([]string{"created_at"}, pageResponse.OrderBy)
}
