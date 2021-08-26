package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/heww/harbor-scanner-fake/api"
	"github.com/heww/harbor-scanner-fake/pkg/config"
	"github.com/heww/harbor-scanner-fake/pkg/db"
	"github.com/heww/harbor-scanner-fake/pkg/scanner"
	"github.com/heww/harbor-scanner-fake/pkg/util"
	"github.com/labstack/echo/v4"
)

type Server struct {
	cfg     *config.Config
	scanner *scanner.Scanner
}

func (s *Server) sendError(ctx echo.Context, err error) error {
	return ctx.JSON(http.StatusInternalServerError, api.ErrorResponse{
		Error: &api.Error{
			Message: util.String(err.Error()),
		},
	})
}

func (s *Server) GetMetadata(ctx echo.Context) error {
	time.Sleep(s.cfg.Server.Delay.Metadata)

	return ctx.JSON(http.StatusOK, s.scanner.Metadata())
}

func (s *Server) AcceptScanRequest(ctx echo.Context) error {
	time.Sleep(s.cfg.Server.Delay.AcceptScanRequest)

	var scanRequest api.ScanRequest
	if err := json.NewDecoder(ctx.Request().Body).Decode(&scanRequest); err != nil {
		return s.sendError(ctx, err)
	}

	id, err := s.scanner.Scan(&scanRequest)
	if err != nil {
		return s.sendError(ctx, err)
	}

	return ctx.JSON(http.StatusAccepted, &api.ScanResponse{Id: id})
}

func (s *Server) GetScanReport(ctx echo.Context, scanRequestId api.ScanRequestId, params api.GetScanReportParams) error {
	time.Sleep(s.cfg.Server.Delay.GetScanReport)

	report, err := s.scanner.GetReport(scanRequestId)
	if err != nil {
		if errors.Is(err, scanner.ErrReportNotFound) {
			return ctx.NoContent(http.StatusNotFound)
		}

		return s.sendError(ctx, err)
	}

	if report == nil {
		return ctx.Redirect(http.StatusFound, ctx.Request().RequestURI)
	}

	return ctx.JSON(http.StatusOK, report)
}

func New(cfg *config.Config) api.ServerInterface {
	db := db.New(cfg.DB.Total)
	scanner := scanner.New(cfg, db)

	return &Server{
		cfg:     cfg,
		scanner: scanner,
	}
}
