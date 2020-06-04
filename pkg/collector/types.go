package collector

type (
	// DeviceStat maps series to value
	DeviceStat map[string]uint64
	// DeviceStats is grouped by ethernet device
	DeviceStats map[string]DeviceStat
)
