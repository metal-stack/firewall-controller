package logger

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewZapLogger(levelString string) (*zap.SugaredLogger, error) {
	level, err := zap.ParseAtomicLevel(levelString)
	if err != nil {
		return nil, fmt.Errorf("unable to parse log level: %w", err)
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = level
	cfg.EncoderConfig.TimeKey = "timestamp"
	cfg.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder

	l, err := cfg.Build()
	if err != nil {
		return nil, fmt.Errorf("can't initialize zap logger: %w", err)
	}

	return l.Sugar(), nil
}
