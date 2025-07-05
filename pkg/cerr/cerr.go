package cerr

import "fmt"

type CustomError error

var (
	IDDontMatch       CustomError = fmt.Errorf("tokens ids doesn't match")
	RefreshDontMatch  CustomError = fmt.Errorf("given and stored refresh tokens doesn't match")
	AccessTokenKilled CustomError = fmt.Errorf("given acces token is not linked to stored refresh token")
)
