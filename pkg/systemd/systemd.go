package systemd

import (
	"context"
	"fmt"
	"path"

	"github.com/coreos/go-systemd/v22/dbus"
)

const (
	modeReplace = "replace"
	jobDone     = "done"
	jobSkipped  = "skipped"
)

func Start(ctx context.Context, unit string) error {
	return withConnection(ctx, func(dbc *dbus.Conn) error {
		return runJob(ctx, unit, "start", dbc.StartUnitContext)
	})
}

func Stop(ctx context.Context, unit string) error {
	return withConnection(ctx, func(dbc *dbus.Conn) error {
		return runJob(ctx, unit, "stop", dbc.StopUnitContext)
	})
}

func Restart(ctx context.Context, unit string) error {
	return withConnection(ctx, func(dbc *dbus.Conn) error {
		return runJob(ctx, unit, "restart", dbc.RestartUnitContext)
	})
}

func Reload(ctx context.Context, unit string) error {
	return withConnection(ctx, func(dbc *dbus.Conn) error {
		return runJob(ctx, unit, "reload", dbc.ReloadUnitContext)
	})
}

func DaemonReload(ctx context.Context) error {
	return withConnection(ctx, func(dbc *dbus.Conn) error {
		return dbc.ReloadContext(ctx)
	})
}

func Enable(ctx context.Context, unit string) error {
	return withConnection(ctx, func(dbc *dbus.Conn) error {
		return enable(ctx, dbc, unit)
	})
}

func Disable(ctx context.Context, unit string) error {
	return withConnection(ctx, func(dbc *dbus.Conn) error {
		return disable(ctx, dbc, unit)
	})
}

func EnableAndStart(ctx context.Context, unit string) error {
	return withConnection(ctx, func(dbc *dbus.Conn) error {
		if err := enable(ctx, dbc, unit); err != nil {
			return err
		}

		return runJob(ctx, unit, "start", dbc.StartUnitContext)
	})
}

func EnableAndRestart(ctx context.Context, unit string) error {
	return withConnection(ctx, func(dbc *dbus.Conn) error {
		if err := enable(ctx, dbc, unit); err != nil {
			return err
		}

		return runJob(ctx, unit, "restart", dbc.RestartUnitContext)
	})
}

// DisableAndStop disables and stops the unit. Missing units are ignored so
// callers can reconcile against units that are not installed in every image.
func DisableAndStop(ctx context.Context, unit string) error {
	return withConnection(ctx, func(dbc *dbus.Conn) error {
		exists, err := unitFileExists(ctx, dbc, unit)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}

		if err := disable(ctx, dbc, unit); err != nil {
			return err
		}

		return runJob(ctx, unit, "stop", dbc.StopUnitContext)
	})
}

func UnitFileExists(ctx context.Context, unit string) (bool, error) {
	var exists bool

	err := withConnection(ctx, func(dbc *dbus.Conn) error {
		var err error
		exists, err = unitFileExists(ctx, dbc, unit)
		return err
	})

	return exists, err
}

// AnyUnitFileEnabled returns true when at least one of the given unit files is
// enabled.
func AnyUnitFileEnabled(ctx context.Context, units ...string) (bool, error) {
	var enabled bool

	err := withConnection(ctx, func(dbc *dbus.Conn) error {
		unitFiles, err := dbc.ListUnitFilesContext(ctx)
		if err != nil {
			return fmt.Errorf("unable to list unit files: %w", err)
		}

		wanted := make(map[string]struct{}, len(units))
		for _, unit := range units {
			wanted[unit] = struct{}{}
		}

		for _, unit := range unitFiles {
			if _, ok := wanted[path.Base(unit.Path)]; !ok {
				continue
			}
			if unit.Type == "enabled" || unit.Type == "enabled-runtime" {
				enabled = true
				return nil
			}
		}

		return nil
	})

	return enabled, err
}

func enable(ctx context.Context, dbc *dbus.Conn, unit string) error {
	if _, _, err := dbc.EnableUnitFilesContext(ctx, []string{unit}, false, false); err != nil {
		return fmt.Errorf("unable to enable unit %s: %w", unit, err)
	}

	return nil
}

func disable(ctx context.Context, dbc *dbus.Conn, unit string) error {
	if _, err := dbc.DisableUnitFilesContext(ctx, []string{unit}, false); err != nil {
		return fmt.Errorf("unable to disable unit %s: %w", unit, err)
	}

	return nil
}

func unitFileExists(ctx context.Context, dbc *dbus.Conn, unit string) (bool, error) {
	units, err := dbc.ListUnitFilesContext(ctx)
	if err != nil {
		return false, fmt.Errorf("unable to list unit files: %w", err)
	}

	for _, unitFile := range units {
		if path.Base(unitFile.Path) == unit {
			return true, nil
		}
	}

	return false, nil
}

func withConnection(ctx context.Context, fn func(*dbus.Conn) error) error {
	dbc, err := dbus.NewWithContext(ctx)
	if err != nil {
		return fmt.Errorf("unable to connect to dbus: %w", err)
	}
	defer dbc.Close()

	return fn(dbc)
}

func runJob(
	ctx context.Context,
	unit string,
	action string,
	run func(context.Context, string, string, chan<- string) (int, error),
) error {
	resultCh := make(chan string, 1)

	if _, err := run(ctx, unit, modeReplace, resultCh); err != nil {
		return fmt.Errorf("unable to %s unit %s: %w", action, unit, err)
	}

	select {
	case result := <-resultCh:
		if result != jobDone && result != jobSkipped {
			return fmt.Errorf("unable to %s unit %s: job %s", action, unit, result)
		}

		return nil
	case <-ctx.Done():
		return fmt.Errorf("unable to %s unit %s: %w", action, unit, ctx.Err())
	}
}
