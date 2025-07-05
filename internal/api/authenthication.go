package api

import (
	"log/slog"
	"medods_test/pkg/cerr"
	"medods_test/pkg/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type Service interface {
	CreateTokens(id uuid.UUID) (*models.Tokens, error)
	RefreshTokens(models.Tokens) (*models.Tokens, error)
	GetID(string) (uuid.UUID, error)
	KillTokens(string) error
}

// @ID			CreateTokens
// @Tags		Authentication
// @Summary	Creates tokens based off given uuid
// @Description
// @Produce	json
// @Success	200	{object}	models.Tokens
// @Failure	400	{object}	error
// @Failure	500	{object}	error
// @Router		/tokens/{id} [get]
func (a *API) CreateTokens(c *fiber.Ctx) error {
	userID, err := uuid.Parse(c.Params("+"))
	if err != nil {
		slog.Error("API: CreateTokens: can't parse given uuid", "error", err)
		return fiber.NewError(400, "can't parse given uuid")
	}
	tokens, err := a.service.CreateTokens(userID)
	if err != nil {
		c.Status(500)
		return err
	}
	return c.JSON(*tokens)
}

// @ID			RefreshTokens
// @Tags		Authentication
// @Summary	Refreshes tokens
// @Description
// @Param Cookie header string true "access_token"
// @Param Cookie header string true "refresh_token"
// @Produce	json
// @Success	200	{object}	models.Tokens
// @Failure	400	{object}	error
// @Failure	500	{object}	error
// @Router		/refresh [get]
func (a *API) RefreshTokens(c *fiber.Ctx) error {
	tokens := models.Tokens{AccessToken: c.Cookies("access_token"), RefreshToken: c.Cookies("refresh_token")}
	refreshedTokens, err := a.service.RefreshTokens(tokens)
	if err != nil {
		if err.Error() == cerr.RefreshDontMatch.Error() {
			return fiber.NewError(400, cerr.RefreshDontMatch.Error())
		}
		if err.Error() == cerr.IDDontMatch.Error() {
			return fiber.NewError(400, cerr.IDDontMatch.Error())
		}
		c.Status(500)
		return err
	}
	return c.JSON(refreshedTokens)
}

// @ID			GetUUID
// @Tags		Authentication
// @Summary	Creates tokens based of given token
// @Param Cookie header string true "access_token"
// @Produce	text/plain
// @Success	200	{object}	string
// @Failure	400	{object}	error
// @Failure	500	{object}	error
// @Router		/id [get]
func (a *API) GetUUID(c *fiber.Ctx) error {
	token := c.Cookies("access_token")
	id, err := a.service.GetID(token)
	if err != nil {
		if err.Error() == cerr.AccessTokenKilled.Error() {
			return fiber.NewError(400, cerr.AccessTokenKilled.Error())
		}
		c.Status(500)
		return err
	}
	return c.SendString(id.String())
}

// @ID			KillTokens
// @Tags		Authentication
// @Summary	Makes current tokens unusable
// @Param Cookie header string true "access_token"
// @Produce	json
// @Success	200
// @Failure	400	{object}	error
// @Failure	500	{object}	error
// @Router		/tokens [delete]
func (a *API) KillTokens(c *fiber.Ctx) error {
	token := c.Cookies("access_token")
	err := a.service.KillTokens(token)

	if err != nil {
		if err.Error() == cerr.RefreshDontMatch.Error() {
			return fiber.NewError(400, cerr.RefreshDontMatch.Error())
		}
		if err.Error() == cerr.IDDontMatch.Error() {
			return fiber.NewError(400, cerr.IDDontMatch.Error())
		}
		c.Status(500)
		return err
	}
	return nil
}
