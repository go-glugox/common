package tests

import (
	"github.com/go-glugox/common"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestCreateToken(t *testing.T) {
	uid := 10
	token, _ := common.CreateToken(uint32(uid))
	assert.NotNil(t, token)
}

func TestTokenValid(t *testing.T)  {

	var uid uint32 = 10
	token, _ := common.CreateToken(uint32(uid))

	// Create a new request using http
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer " + token)


	err := common.TokenValid(req)
	assert.Nil(t, err)

}