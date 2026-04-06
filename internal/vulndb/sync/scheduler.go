package sync

import (
	"context"
	"log/slog"
	"time"

	"dependency-guardian/internal/config"
)

// Scheduler runs periodic full syncs, delta syncs, and metrics updates.
type Scheduler struct {
	syncer *Syncer
	cfg    config.SyncConfig
	logger *slog.Logger
	cancel context.CancelFunc
}

// NewScheduler creates a new sync scheduler.
func NewScheduler(syncer *Syncer, cfg config.SyncConfig, logger *slog.Logger) *Scheduler {
	return &Scheduler{
		syncer: syncer,
		cfg:    cfg,
		logger: logger.With("component", "vulndb-scheduler"),
	}
}

// Start launches the background sync goroutines and returns immediately.
// Call Stop() to shut them down.
func (s *Scheduler) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)

	// Delta sync loop.
	if s.cfg.DeltaSyncInterval > 0 {
		go s.loop(ctx, "delta-sync", s.cfg.DeltaSyncInterval, func(ctx context.Context) {
			if err := s.syncer.DeltaSync(ctx); err != nil {
				s.logger.Error("delta sync failed", "error", err)
			}
		})
	}

	// Full sync loop.
	if s.cfg.FullSyncInterval > 0 {
		go s.loop(ctx, "full-sync", s.cfg.FullSyncInterval, func(ctx context.Context) {
			if err := s.syncer.SeedAll(ctx); err != nil {
				s.logger.Error("full sync failed", "error", err)
			}
		})
	}

	// Metrics update loop.
	if s.cfg.MetricsInterval > 0 {
		go s.loop(ctx, "metrics", s.cfg.MetricsInterval, func(ctx context.Context) {
			if err := s.syncer.store.UpdateAllMetrics(ctx); err != nil {
				s.logger.Error("metrics update failed", "error", err)
			}
		})
	}

	s.logger.Info("sync scheduler started",
		"full_interval", s.cfg.FullSyncInterval,
		"delta_interval", s.cfg.DeltaSyncInterval,
		"metrics_interval", s.cfg.MetricsInterval,
	)
}

// Stop shuts down all background sync goroutines.
func (s *Scheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

// loop runs fn on the given interval until the context is cancelled.
func (s *Scheduler) loop(ctx context.Context, name string, interval time.Duration, fn func(context.Context)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("stopping sync loop", "loop", name)
			return
		case <-ticker.C:
			s.logger.Debug("running sync loop", "loop", name)
			fn(ctx)
		}
	}
}
