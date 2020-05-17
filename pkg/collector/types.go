package collector

type (
	// DeviceStat maps series to value
	DeviceStat map[string]int64
	// DeviceStats is grouped by ethernet device
	DeviceStats map[string]DeviceStat
)
