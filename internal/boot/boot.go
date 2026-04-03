package boot

import (
	"context"
	"log"

	"cdua-org/ReconSR/internal/controller"
	"cdua-org/ReconSR/internal/i18n"
	"cdua-org/ReconSR/internal/scopemanager"
)

// Init prepares the application environment, languages, and core engine.
func Init(ctx context.Context, langPath string) error {
	if err := i18n.Setup(langPath); err != nil {
		log.Printf("Warning: could not setup language: %v", err)
	}

	if err := scopemanager.Setup(); err != nil {
		log.Printf("Warning: could not setup scope: %v", err)
	}

	if err := controller.SyncConfig(ctx); err != nil {
		return err
	}

	return nil
}
