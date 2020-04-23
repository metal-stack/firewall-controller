package collector

var metrics = `
# HELP go_gc_duration_seconds A summary of the pause duration of garbage collection cycles.
# TYPE go_gc_duration_seconds summary
go_gc_duration_seconds{quantile="0"} 6.84e-06
go_gc_duration_seconds{quantile="0.25"} 2.0034e-05
go_gc_duration_seconds{quantile="0.5"} 3.5752e-05
go_gc_duration_seconds{quantile="0.75"} 3.7573e-05
go_gc_duration_seconds{quantile="1"} 0.006580516
go_gc_duration_seconds_sum 0.016863707
go_gc_duration_seconds_count 264
# HELP go_goroutines Number of goroutines that currently exist.
# TYPE go_goroutines gauge
go_goroutines 8
# HELP go_info Information about the Go environment.
# TYPE go_info gauge
go_info{version="go1.14.2"} 1
# HELP go_memstats_alloc_bytes Number of bytes allocated and still in use.
# TYPE go_memstats_alloc_bytes gauge
go_memstats_alloc_bytes 652984
# HELP go_memstats_alloc_bytes_total Total number of bytes allocated, even if freed.
# TYPE go_memstats_alloc_bytes_total counter
go_memstats_alloc_bytes_total 1.52426912e+08
# HELP go_memstats_buck_hash_sys_bytes Number of bytes used by the profiling bucket hash table.
# TYPE go_memstats_buck_hash_sys_bytes gauge
go_memstats_buck_hash_sys_bytes 1.483784e+06
# HELP go_memstats_frees_total Total number of frees.
# TYPE go_memstats_frees_total counter
go_memstats_frees_total 1.32123e+06
# HELP go_memstats_gc_cpu_fraction The fraction of this program's available CPU time used by the GC since the program started.
# TYPE go_memstats_gc_cpu_fraction gauge
go_memstats_gc_cpu_fraction 2.549506301382549e-06
# HELP go_memstats_gc_sys_bytes Number of bytes used for garbage collection system metadata.
# TYPE go_memstats_gc_sys_bytes gauge
go_memstats_gc_sys_bytes 3.57812e+06
# HELP go_memstats_heap_alloc_bytes Number of heap bytes allocated and still in use.
# TYPE go_memstats_heap_alloc_bytes gauge
go_memstats_heap_alloc_bytes 652984
# HELP go_memstats_heap_idle_bytes Number of heap bytes waiting to be used.
# TYPE go_memstats_heap_idle_bytes gauge
go_memstats_heap_idle_bytes 6.4462848e+07
# HELP go_memstats_heap_inuse_bytes Number of heap bytes that are in use.
# TYPE go_memstats_heap_inuse_bytes gauge
go_memstats_heap_inuse_bytes 1.859584e+06
# HELP go_memstats_heap_objects Number of allocated objects.
# TYPE go_memstats_heap_objects gauge
go_memstats_heap_objects 3393
# HELP go_memstats_heap_released_bytes Number of heap bytes released to OS.
# TYPE go_memstats_heap_released_bytes gauge
go_memstats_heap_released_bytes 6.4405504e+07
# HELP go_memstats_heap_sys_bytes Number of heap bytes obtained from system.
# TYPE go_memstats_heap_sys_bytes gauge
go_memstats_heap_sys_bytes 6.6322432e+07
# HELP go_memstats_last_gc_time_seconds Number of seconds since 1970 of last garbage collection.
# TYPE go_memstats_last_gc_time_seconds gauge
go_memstats_last_gc_time_seconds 1.5873128183900182e+09
# HELP go_memstats_lookups_total Total number of pointer lookups.
# TYPE go_memstats_lookups_total counter
go_memstats_lookups_total 0
# HELP go_memstats_mallocs_total Total number of mallocs.
# TYPE go_memstats_mallocs_total counter
go_memstats_mallocs_total 1.324623e+06
# HELP go_memstats_mcache_inuse_bytes Number of bytes in use by mcache structures.
# TYPE go_memstats_mcache_inuse_bytes gauge
go_memstats_mcache_inuse_bytes 6944
# HELP go_memstats_mcache_sys_bytes Number of bytes used for mcache structures obtained from system.
# TYPE go_memstats_mcache_sys_bytes gauge
go_memstats_mcache_sys_bytes 16384
# HELP go_memstats_mspan_inuse_bytes Number of bytes in use by mspan structures.
# TYPE go_memstats_mspan_inuse_bytes gauge
go_memstats_mspan_inuse_bytes 78064
# HELP go_memstats_mspan_sys_bytes Number of bytes used for mspan structures obtained from system.
# TYPE go_memstats_mspan_sys_bytes gauge
go_memstats_mspan_sys_bytes 114688
# HELP go_memstats_next_gc_bytes Number of heap bytes when next garbage collection will take place.
# TYPE go_memstats_next_gc_bytes gauge
go_memstats_next_gc_bytes 4.194304e+06
# HELP go_memstats_other_sys_bytes Number of bytes used for other system allocations.
# TYPE go_memstats_other_sys_bytes gauge
go_memstats_other_sys_bytes 1.180656e+06
# HELP go_memstats_stack_inuse_bytes Number of bytes in use by the stack allocator.
# TYPE go_memstats_stack_inuse_bytes gauge
go_memstats_stack_inuse_bytes 786432
# HELP go_memstats_stack_sys_bytes Number of bytes obtained from system for stack allocator.
# TYPE go_memstats_stack_sys_bytes gauge
go_memstats_stack_sys_bytes 786432
# HELP go_memstats_sys_bytes Number of bytes obtained from system.
# TYPE go_memstats_sys_bytes gauge
go_memstats_sys_bytes 7.3482496e+07
# HELP go_threads Number of OS threads created.
# TYPE go_threads gauge
go_threads 12
# HELP node_arp_entries ARP entries by device
# TYPE node_arp_entries gauge
node_arp_entries{device="enp0s31f6"} 2
# HELP node_boot_time_seconds Node boot time, in unixtime.
# TYPE node_boot_time_seconds gauge
node_boot_time_seconds 1.587271723e+09
# HELP node_context_switches_total Total number of context switches.
# TYPE node_context_switches_total counter
node_context_switches_total 1.32652262e+08
# HELP node_cooling_device_cur_state Current throttle state of the cooling device
# TYPE node_cooling_device_cur_state gauge
node_cooling_device_cur_state{name="0",type="Fan"} 0
node_cooling_device_cur_state{name="1",type="Fan"} 0
node_cooling_device_cur_state{name="2",type="Fan"} 0
node_cooling_device_cur_state{name="3",type="Fan"} 0
node_cooling_device_cur_state{name="4",type="Fan"} 0
node_cooling_device_cur_state{name="5",type="Processor"} 0
node_cooling_device_cur_state{name="6",type="Processor"} 0
node_cooling_device_cur_state{name="7",type="Processor"} 0
node_cooling_device_cur_state{name="8",type="Processor"} 0
node_cooling_device_cur_state{name="9",type="intel_powerclamp"} -1
# HELP node_cooling_device_max_state Maximum throttle state of the cooling device
# TYPE node_cooling_device_max_state gauge
node_cooling_device_max_state{name="0",type="Fan"} 1
node_cooling_device_max_state{name="1",type="Fan"} 1
node_cooling_device_max_state{name="2",type="Fan"} 1
node_cooling_device_max_state{name="3",type="Fan"} 1
node_cooling_device_max_state{name="4",type="Fan"} 1
node_cooling_device_max_state{name="5",type="Processor"} 3
node_cooling_device_max_state{name="6",type="Processor"} 3
node_cooling_device_max_state{name="7",type="Processor"} 3
node_cooling_device_max_state{name="8",type="Processor"} 3
node_cooling_device_max_state{name="9",type="intel_powerclamp"} 50
# HELP node_cpu_core_throttles_total Number of times this cpu core has been throttled.
# TYPE node_cpu_core_throttles_total counter
node_cpu_core_throttles_total{core="0",package="0"} 0
node_cpu_core_throttles_total{core="1",package="0"} 0
node_cpu_core_throttles_total{core="2",package="0"} 0
node_cpu_core_throttles_total{core="3",package="0"} 0
# HELP node_cpu_frequency_max_hertz Maximum cpu thread frequency in hertz.
# TYPE node_cpu_frequency_max_hertz gauge
node_cpu_frequency_max_hertz{cpu="0"} 3.9e+09
node_cpu_frequency_max_hertz{cpu="1"} 3.9e+09
node_cpu_frequency_max_hertz{cpu="2"} 3.9e+09
node_cpu_frequency_max_hertz{cpu="3"} 3.9e+09
# HELP node_cpu_frequency_min_hertz Minimum cpu thread frequency in hertz.
# TYPE node_cpu_frequency_min_hertz gauge
node_cpu_frequency_min_hertz{cpu="0"} 8e+08
node_cpu_frequency_min_hertz{cpu="1"} 8e+08
node_cpu_frequency_min_hertz{cpu="2"} 8e+08
node_cpu_frequency_min_hertz{cpu="3"} 8e+08
# HELP node_cpu_guest_seconds_total Seconds the cpus spent in guests (VMs) for each mode.
# TYPE node_cpu_guest_seconds_total counter
node_cpu_guest_seconds_total{cpu="0",mode="nice"} 0
node_cpu_guest_seconds_total{cpu="0",mode="user"} 0
node_cpu_guest_seconds_total{cpu="1",mode="nice"} 0
node_cpu_guest_seconds_total{cpu="1",mode="user"} 0
node_cpu_guest_seconds_total{cpu="2",mode="nice"} 0
node_cpu_guest_seconds_total{cpu="2",mode="user"} 0
node_cpu_guest_seconds_total{cpu="3",mode="nice"} 0
node_cpu_guest_seconds_total{cpu="3",mode="user"} 0
# HELP node_cpu_package_throttles_total Number of times this cpu package has been throttled.
# TYPE node_cpu_package_throttles_total counter
node_cpu_package_throttles_total{package="0"} 0
# HELP node_cpu_scaling_frequency_hertz Current scaled cpu thread frequency in hertz.
# TYPE node_cpu_scaling_frequency_hertz gauge
node_cpu_scaling_frequency_hertz{cpu="0"} 3.56865e+09
node_cpu_scaling_frequency_hertz{cpu="1"} 3.478945e+09
node_cpu_scaling_frequency_hertz{cpu="2"} 3.537611e+09
node_cpu_scaling_frequency_hertz{cpu="3"} 3.618305e+09
# HELP node_cpu_scaling_frequency_max_hertz Maximum scaled cpu thread frequency in hertz.
# TYPE node_cpu_scaling_frequency_max_hertz gauge
node_cpu_scaling_frequency_max_hertz{cpu="0"} 3.9e+09
node_cpu_scaling_frequency_max_hertz{cpu="1"} 3.9e+09
node_cpu_scaling_frequency_max_hertz{cpu="2"} 3.9e+09
node_cpu_scaling_frequency_max_hertz{cpu="3"} 3.9e+09
# HELP node_cpu_scaling_frequency_min_hertz Minimum scaled cpu thread frequency in hertz.
# TYPE node_cpu_scaling_frequency_min_hertz gauge
node_cpu_scaling_frequency_min_hertz{cpu="0"} 8e+08
node_cpu_scaling_frequency_min_hertz{cpu="1"} 8e+08
node_cpu_scaling_frequency_min_hertz{cpu="2"} 8e+08
node_cpu_scaling_frequency_min_hertz{cpu="3"} 8e+08
# HELP node_cpu_seconds_total Seconds the cpus spent in each mode.
# TYPE node_cpu_seconds_total counter
node_cpu_seconds_total{cpu="0",mode="idle"} 37267.84
node_cpu_seconds_total{cpu="0",mode="iowait"} 38.88
node_cpu_seconds_total{cpu="0",mode="irq"} 0
node_cpu_seconds_total{cpu="0",mode="nice"} 6.64
node_cpu_seconds_total{cpu="0",mode="softirq"} 461.32
node_cpu_seconds_total{cpu="0",mode="steal"} 0
node_cpu_seconds_total{cpu="0",mode="system"} 660.64
node_cpu_seconds_total{cpu="0",mode="user"} 2997.76
node_cpu_seconds_total{cpu="1",mode="idle"} 37225.21
node_cpu_seconds_total{cpu="1",mode="iowait"} 41.04
node_cpu_seconds_total{cpu="1",mode="irq"} 0
node_cpu_seconds_total{cpu="1",mode="nice"} 2.96
node_cpu_seconds_total{cpu="1",mode="softirq"} 405.9
node_cpu_seconds_total{cpu="1",mode="steal"} 0
node_cpu_seconds_total{cpu="1",mode="system"} 651.86
node_cpu_seconds_total{cpu="1",mode="user"} 3006.85
node_cpu_seconds_total{cpu="2",mode="idle"} 37266.24
node_cpu_seconds_total{cpu="2",mode="iowait"} 40.61
node_cpu_seconds_total{cpu="2",mode="irq"} 0
node_cpu_seconds_total{cpu="2",mode="nice"} 6.64
node_cpu_seconds_total{cpu="2",mode="softirq"} 283.29
node_cpu_seconds_total{cpu="2",mode="steal"} 0
node_cpu_seconds_total{cpu="2",mode="system"} 650.34
node_cpu_seconds_total{cpu="2",mode="user"} 2992.6
node_cpu_seconds_total{cpu="3",mode="idle"} 37268.29
node_cpu_seconds_total{cpu="3",mode="iowait"} 40.78
node_cpu_seconds_total{cpu="3",mode="irq"} 0
node_cpu_seconds_total{cpu="3",mode="nice"} 2.46
node_cpu_seconds_total{cpu="3",mode="softirq"} 201.6
node_cpu_seconds_total{cpu="3",mode="steal"} 0
node_cpu_seconds_total{cpu="3",mode="system"} 655.88
node_cpu_seconds_total{cpu="3",mode="user"} 3001.22
# HELP node_disk_discard_time_seconds_total This is the total number of seconds spent by all discards.
# TYPE node_disk_discard_time_seconds_total counter
node_disk_discard_time_seconds_total{device="dm-0"} 0
node_disk_discard_time_seconds_total{device="dm-1"} 0
node_disk_discard_time_seconds_total{device="dm-2"} 0
node_disk_discard_time_seconds_total{device="dm-3"} 0
node_disk_discard_time_seconds_total{device="dm-4"} 0
node_disk_discard_time_seconds_total{device="nvme0n1"} 0
node_disk_discard_time_seconds_total{device="sr0"} 0
# HELP node_disk_discarded_sectors_total The total number of sectors discarded successfully.
# TYPE node_disk_discarded_sectors_total counter
node_disk_discarded_sectors_total{device="dm-0"} 0
node_disk_discarded_sectors_total{device="dm-1"} 0
node_disk_discarded_sectors_total{device="dm-2"} 0
node_disk_discarded_sectors_total{device="dm-3"} 0
node_disk_discarded_sectors_total{device="dm-4"} 0
node_disk_discarded_sectors_total{device="nvme0n1"} 0
node_disk_discarded_sectors_total{device="sr0"} 0
# HELP node_disk_discards_completed_total The total number of discards completed successfully.
# TYPE node_disk_discards_completed_total counter
node_disk_discards_completed_total{device="dm-0"} 0
node_disk_discards_completed_total{device="dm-1"} 0
node_disk_discards_completed_total{device="dm-2"} 0
node_disk_discards_completed_total{device="dm-3"} 0
node_disk_discards_completed_total{device="dm-4"} 0
node_disk_discards_completed_total{device="nvme0n1"} 0
node_disk_discards_completed_total{device="sr0"} 0
# HELP node_disk_discards_merged_total The total number of discards merged.
# TYPE node_disk_discards_merged_total counter
node_disk_discards_merged_total{device="dm-0"} 0
node_disk_discards_merged_total{device="dm-1"} 0
node_disk_discards_merged_total{device="dm-2"} 0
node_disk_discards_merged_total{device="dm-3"} 0
node_disk_discards_merged_total{device="dm-4"} 0
node_disk_discards_merged_total{device="nvme0n1"} 0
node_disk_discards_merged_total{device="sr0"} 0
# HELP node_disk_io_now The number of I/Os currently in progress.
# TYPE node_disk_io_now gauge
node_disk_io_now{device="dm-0"} 0
node_disk_io_now{device="dm-1"} 0
node_disk_io_now{device="dm-2"} 0
node_disk_io_now{device="dm-3"} 0
node_disk_io_now{device="dm-4"} 0
node_disk_io_now{device="nvme0n1"} 0
node_disk_io_now{device="sr0"} 0
# HELP node_disk_io_time_seconds_total Total seconds spent doing I/Os.
# TYPE node_disk_io_time_seconds_total counter
node_disk_io_time_seconds_total{device="dm-0"} 112.11200000000001
node_disk_io_time_seconds_total{device="dm-1"} 1.028
node_disk_io_time_seconds_total{device="dm-2"} 189.42000000000002
node_disk_io_time_seconds_total{device="dm-3"} 4.088
node_disk_io_time_seconds_total{device="dm-4"} 0.152
node_disk_io_time_seconds_total{device="nvme0n1"} 300.724
node_disk_io_time_seconds_total{device="sr0"} 0
# HELP node_disk_io_time_weighted_seconds_total The weighted # of seconds spent doing I/Os.
# TYPE node_disk_io_time_weighted_seconds_total counter
node_disk_io_time_weighted_seconds_total{device="dm-0"} 136.1
node_disk_io_time_weighted_seconds_total{device="dm-1"} 81.144
node_disk_io_time_weighted_seconds_total{device="dm-2"} 288.144
node_disk_io_time_weighted_seconds_total{device="dm-3"} 9.404
node_disk_io_time_weighted_seconds_total{device="dm-4"} 0.032
node_disk_io_time_weighted_seconds_total{device="nvme0n1"} 140.268
node_disk_io_time_weighted_seconds_total{device="sr0"} 0
# HELP node_disk_read_bytes_total The total number of bytes read successfully.
# TYPE node_disk_read_bytes_total counter
node_disk_read_bytes_total{device="dm-0"} 1.927394304e+09
node_disk_read_bytes_total{device="dm-1"} 3.178496e+06
node_disk_read_bytes_total{device="dm-2"} 1.59523328e+09
node_disk_read_bytes_total{device="dm-3"} 1.3382144e+08
node_disk_read_bytes_total{device="dm-4"} 5.563392e+06
node_disk_read_bytes_total{device="nvme0n1"} 3.682527232e+09
node_disk_read_bytes_total{device="sr0"} 0
# HELP node_disk_read_time_seconds_total The total number of seconds spent by all reads.
# TYPE node_disk_read_time_seconds_total counter
node_disk_read_time_seconds_total{device="dm-0"} 12.8
node_disk_read_time_seconds_total{device="dm-1"} 0.02
node_disk_read_time_seconds_total{device="dm-2"} 29.108
node_disk_read_time_seconds_total{device="dm-3"} 4.284
node_disk_read_time_seconds_total{device="dm-4"} 0.02
node_disk_read_time_seconds_total{device="nvme0n1"} 21.906
node_disk_read_time_seconds_total{device="sr0"} 0
# HELP node_disk_reads_completed_total The total number of reads completed successfully.
# TYPE node_disk_reads_completed_total counter
node_disk_reads_completed_total{device="dm-0"} 66606
node_disk_reads_completed_total{device="dm-1"} 139
node_disk_reads_completed_total{device="dm-2"} 188758
node_disk_reads_completed_total{device="dm-3"} 26636
node_disk_reads_completed_total{device="dm-4"} 258
node_disk_reads_completed_total{device="nvme0n1"} 204162
node_disk_reads_completed_total{device="sr0"} 0
# HELP node_disk_reads_merged_total The total number of reads merged.
# TYPE node_disk_reads_merged_total counter
node_disk_reads_merged_total{device="dm-0"} 0
node_disk_reads_merged_total{device="dm-1"} 0
node_disk_reads_merged_total{device="dm-2"} 0
node_disk_reads_merged_total{device="dm-3"} 0
node_disk_reads_merged_total{device="dm-4"} 0
node_disk_reads_merged_total{device="nvme0n1"} 79903
node_disk_reads_merged_total{device="sr0"} 0
# HELP node_disk_write_time_seconds_total This is the total number of seconds spent by all writes.
# TYPE node_disk_write_time_seconds_total counter
node_disk_write_time_seconds_total{device="dm-0"} 123.3
node_disk_write_time_seconds_total{device="dm-1"} 81.124
node_disk_write_time_seconds_total{device="dm-2"} 259.036
node_disk_write_time_seconds_total{device="dm-3"} 5.12
node_disk_write_time_seconds_total{device="dm-4"} 0.012
node_disk_write_time_seconds_total{device="nvme0n1"} 470.559
node_disk_write_time_seconds_total{device="sr0"} 0
# HELP node_disk_writes_completed_total The total number of writes completed successfully.
# TYPE node_disk_writes_completed_total counter
node_disk_writes_completed_total{device="dm-0"} 256641
node_disk_writes_completed_total{device="dm-1"} 95588
node_disk_writes_completed_total{device="dm-2"} 515810
node_disk_writes_completed_total{device="dm-3"} 7348
node_disk_writes_completed_total{device="dm-4"} 29
node_disk_writes_completed_total{device="nvme0n1"} 545980
node_disk_writes_completed_total{device="sr0"} 0
# HELP node_disk_writes_merged_total The number of writes merged.
# TYPE node_disk_writes_merged_total counter
node_disk_writes_merged_total{device="dm-0"} 0
node_disk_writes_merged_total{device="dm-1"} 0
node_disk_writes_merged_total{device="dm-2"} 0
node_disk_writes_merged_total{device="dm-3"} 0
node_disk_writes_merged_total{device="dm-4"} 0
node_disk_writes_merged_total{device="nvme0n1"} 329458
node_disk_writes_merged_total{device="sr0"} 0
# HELP node_disk_written_bytes_total The total number of bytes written successfully.
# TYPE node_disk_written_bytes_total counter
node_disk_written_bytes_total{device="dm-0"} 3.05354752e+09
node_disk_written_bytes_total{device="dm-1"} 3.91528448e+08
node_disk_written_bytes_total{device="dm-2"} 7.314264064e+09
node_disk_written_bytes_total{device="dm-3"} 1.04783872e+08
node_disk_written_bytes_total{device="dm-4"} 90112
node_disk_written_bytes_total{device="nvme0n1"} 1.0764263424e+10
node_disk_written_bytes_total{device="sr0"} 0
# HELP node_entropy_available_bits Bits of available entropy.
# TYPE node_entropy_available_bits gauge
node_entropy_available_bits 2574
# HELP node_exporter_build_info A metric with a constant '1' value labeled by version, revision, branch, and goversion from which node_exporter was built.
# TYPE node_exporter_build_info gauge
node_exporter_build_info{branch="master",goversion="go1.14.2",revision="fa4edd700ebc1b3614bcd953c215d3f2ab2e0b35",version="1.0.0-rc.0"} 1
# HELP node_filefd_allocated File descriptor statistics: allocated.
# TYPE node_filefd_allocated gauge
node_filefd_allocated 20896
# HELP node_filefd_maximum File descriptor statistics: maximum.
# TYPE node_filefd_maximum gauge
node_filefd_maximum 1.524081e+06
# HELP node_filesystem_avail_bytes Filesystem space available to non-root users in bytes.
# TYPE node_filesystem_avail_bytes gauge
node_filesystem_avail_bytes{device="/dev/fuse",fstype="fuse",mountpoint="/run/user/1000/doc"} 0
node_filesystem_avail_bytes{device="/dev/mapper/ubuntu--vg-lv_docker",fstype="ext4",mountpoint="/var/lib/docker"} 1.18628352e+09
node_filesystem_avail_bytes{device="/dev/mapper/ubuntu--vg-lv_home",fstype="ext4",mountpoint="/home"} 3.014873088e+09
node_filesystem_avail_bytes{device="/dev/mapper/ubuntu--vg-lv_libvirt",fstype="ext4",mountpoint="/var/lib/libvirt"} 4.7185104896e+10
node_filesystem_avail_bytes{device="/dev/mapper/ubuntu--vg-root",fstype="ext4",mountpoint="/"} 4.48886784e+09
node_filesystem_avail_bytes{device="/dev/nvme0n1p1",fstype="vfat",mountpoint="/boot/efi"} 5.2760576e+08
node_filesystem_avail_bytes{device="/dev/nvme0n1p2",fstype="ext2",mountpoint="/boot"} 8.6950912e+07
node_filesystem_avail_bytes{device="gvfsd-fuse",fstype="fuse.gvfsd-fuse",mountpoint="/run/user/1000/gvfs"} 0
node_filesystem_avail_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run"} 1.565364224e+09
node_filesystem_avail_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run/lock"} 5.238784e+06
node_filesystem_avail_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run/snapd/ns"} 1.565364224e+09
node_filesystem_avail_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run/user/1000"} 1.555673088e+09
node_filesystem_avail_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run/user/1001"} 1.567596544e+09
# HELP node_filesystem_device_error Whether an error occurred while getting statistics for the given device.
# TYPE node_filesystem_device_error gauge
node_filesystem_device_error{device="/dev/fuse",fstype="fuse",mountpoint="/run/user/1000/doc"} 0
node_filesystem_device_error{device="/dev/fuse",fstype="fuse",mountpoint="/run/user/1001/doc"} 1
node_filesystem_device_error{device="/dev/mapper/ubuntu--vg-lv_docker",fstype="ext4",mountpoint="/var/lib/docker"} 0
node_filesystem_device_error{device="/dev/mapper/ubuntu--vg-lv_home",fstype="ext4",mountpoint="/home"} 0
node_filesystem_device_error{device="/dev/mapper/ubuntu--vg-lv_libvirt",fstype="ext4",mountpoint="/var/lib/libvirt"} 0
node_filesystem_device_error{device="/dev/mapper/ubuntu--vg-root",fstype="ext4",mountpoint="/"} 0
node_filesystem_device_error{device="/dev/nvme0n1p1",fstype="vfat",mountpoint="/boot/efi"} 0
node_filesystem_device_error{device="/dev/nvme0n1p2",fstype="ext2",mountpoint="/boot"} 0
node_filesystem_device_error{device="gvfsd-fuse",fstype="fuse.gvfsd-fuse",mountpoint="/run/user/1000/gvfs"} 0
node_filesystem_device_error{device="gvfsd-fuse",fstype="fuse.gvfsd-fuse",mountpoint="/run/user/1001/gvfs"} 1
node_filesystem_device_error{device="tmpfs",fstype="tmpfs",mountpoint="/run"} 0
node_filesystem_device_error{device="tmpfs",fstype="tmpfs",mountpoint="/run/lock"} 0
node_filesystem_device_error{device="tmpfs",fstype="tmpfs",mountpoint="/run/snapd/ns"} 0
node_filesystem_device_error{device="tmpfs",fstype="tmpfs",mountpoint="/run/user/1000"} 0
node_filesystem_device_error{device="tmpfs",fstype="tmpfs",mountpoint="/run/user/1001"} 0
# HELP node_filesystem_files Filesystem total file nodes.
# TYPE node_filesystem_files gauge
node_filesystem_files{device="/dev/fuse",fstype="fuse",mountpoint="/run/user/1000/doc"} 0
node_filesystem_files{device="/dev/mapper/ubuntu--vg-lv_docker",fstype="ext4",mountpoint="/var/lib/docker"} 655360
node_filesystem_files{device="/dev/mapper/ubuntu--vg-lv_home",fstype="ext4",mountpoint="/home"} 3.2768e+06
node_filesystem_files{device="/dev/mapper/ubuntu--vg-lv_libvirt",fstype="ext4",mountpoint="/var/lib/libvirt"} 3.2768e+06
node_filesystem_files{device="/dev/mapper/ubuntu--vg-root",fstype="ext4",mountpoint="/"} 1.31072e+06
node_filesystem_files{device="/dev/nvme0n1p1",fstype="vfat",mountpoint="/boot/efi"} 0
node_filesystem_files{device="/dev/nvme0n1p2",fstype="ext2",mountpoint="/boot"} 62496
node_filesystem_files{device="gvfsd-fuse",fstype="fuse.gvfsd-fuse",mountpoint="/run/user/1000/gvfs"} 0
node_filesystem_files{device="tmpfs",fstype="tmpfs",mountpoint="/run"} 1.913625e+06
node_filesystem_files{device="tmpfs",fstype="tmpfs",mountpoint="/run/lock"} 1.913625e+06
node_filesystem_files{device="tmpfs",fstype="tmpfs",mountpoint="/run/snapd/ns"} 1.913625e+06
node_filesystem_files{device="tmpfs",fstype="tmpfs",mountpoint="/run/user/1000"} 1.913625e+06
node_filesystem_files{device="tmpfs",fstype="tmpfs",mountpoint="/run/user/1001"} 1.913625e+06
# HELP node_filesystem_files_free Filesystem total free file nodes.
# TYPE node_filesystem_files_free gauge
node_filesystem_files_free{device="/dev/fuse",fstype="fuse",mountpoint="/run/user/1000/doc"} 0
node_filesystem_files_free{device="/dev/mapper/ubuntu--vg-lv_docker",fstype="ext4",mountpoint="/var/lib/docker"} 411472
node_filesystem_files_free{device="/dev/mapper/ubuntu--vg-lv_home",fstype="ext4",mountpoint="/home"} 2.323531e+06
node_filesystem_files_free{device="/dev/mapper/ubuntu--vg-lv_libvirt",fstype="ext4",mountpoint="/var/lib/libvirt"} 3.27676e+06
node_filesystem_files_free{device="/dev/mapper/ubuntu--vg-root",fstype="ext4",mountpoint="/"} 1.023337e+06
node_filesystem_files_free{device="/dev/nvme0n1p1",fstype="vfat",mountpoint="/boot/efi"} 0
node_filesystem_files_free{device="/dev/nvme0n1p2",fstype="ext2",mountpoint="/boot"} 62181
node_filesystem_files_free{device="gvfsd-fuse",fstype="fuse.gvfsd-fuse",mountpoint="/run/user/1000/gvfs"} 0
node_filesystem_files_free{device="tmpfs",fstype="tmpfs",mountpoint="/run"} 1.912331e+06
node_filesystem_files_free{device="tmpfs",fstype="tmpfs",mountpoint="/run/lock"} 1.913618e+06
node_filesystem_files_free{device="tmpfs",fstype="tmpfs",mountpoint="/run/snapd/ns"} 1.912331e+06
node_filesystem_files_free{device="tmpfs",fstype="tmpfs",mountpoint="/run/user/1000"} 1.913535e+06
node_filesystem_files_free{device="tmpfs",fstype="tmpfs",mountpoint="/run/user/1001"} 1.913584e+06
# HELP node_filesystem_free_bytes Filesystem free space in bytes.
# TYPE node_filesystem_free_bytes gauge
node_filesystem_free_bytes{device="/dev/fuse",fstype="fuse",mountpoint="/run/user/1000/doc"} 0
node_filesystem_free_bytes{device="/dev/mapper/ubuntu--vg-lv_docker",fstype="ext4",mountpoint="/var/lib/docker"} 1.739931648e+09
node_filesystem_free_bytes{device="/dev/mapper/ubuntu--vg-lv_home",fstype="ext4",mountpoint="/home"} 5.522710528e+09
node_filesystem_free_bytes{device="/dev/mapper/ubuntu--vg-lv_libvirt",fstype="ext4",mountpoint="/var/lib/libvirt"} 4.9886236672e+10
node_filesystem_free_bytes{device="/dev/mapper/ubuntu--vg-root",fstype="ext4",mountpoint="/"} 5.579382784e+09
node_filesystem_free_bytes{device="/dev/nvme0n1p1",fstype="vfat",mountpoint="/boot/efi"} 5.2760576e+08
node_filesystem_free_bytes{device="/dev/nvme0n1p2",fstype="ext2",mountpoint="/boot"} 9.974272e+07
node_filesystem_free_bytes{device="gvfsd-fuse",fstype="fuse.gvfsd-fuse",mountpoint="/run/user/1000/gvfs"} 0
node_filesystem_free_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run"} 1.565364224e+09
node_filesystem_free_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run/lock"} 5.238784e+06
node_filesystem_free_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run/snapd/ns"} 1.565364224e+09
node_filesystem_free_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run/user/1000"} 1.555673088e+09
node_filesystem_free_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run/user/1001"} 1.567596544e+09
# HELP node_filesystem_readonly Filesystem read-only status.
# TYPE node_filesystem_readonly gauge
node_filesystem_readonly{device="/dev/fuse",fstype="fuse",mountpoint="/run/user/1000/doc"} 0
node_filesystem_readonly{device="/dev/mapper/ubuntu--vg-lv_docker",fstype="ext4",mountpoint="/var/lib/docker"} 0
node_filesystem_readonly{device="/dev/mapper/ubuntu--vg-lv_home",fstype="ext4",mountpoint="/home"} 0
node_filesystem_readonly{device="/dev/mapper/ubuntu--vg-lv_libvirt",fstype="ext4",mountpoint="/var/lib/libvirt"} 0
node_filesystem_readonly{device="/dev/mapper/ubuntu--vg-root",fstype="ext4",mountpoint="/"} 0
node_filesystem_readonly{device="/dev/nvme0n1p1",fstype="vfat",mountpoint="/boot/efi"} 0
node_filesystem_readonly{device="/dev/nvme0n1p2",fstype="ext2",mountpoint="/boot"} 0
node_filesystem_readonly{device="gvfsd-fuse",fstype="fuse.gvfsd-fuse",mountpoint="/run/user/1000/gvfs"} 0
node_filesystem_readonly{device="tmpfs",fstype="tmpfs",mountpoint="/run"} 0
node_filesystem_readonly{device="tmpfs",fstype="tmpfs",mountpoint="/run/lock"} 0
node_filesystem_readonly{device="tmpfs",fstype="tmpfs",mountpoint="/run/snapd/ns"} 0
node_filesystem_readonly{device="tmpfs",fstype="tmpfs",mountpoint="/run/user/1000"} 0
node_filesystem_readonly{device="tmpfs",fstype="tmpfs",mountpoint="/run/user/1001"} 0
# HELP node_filesystem_size_bytes Filesystem size in bytes.
# TYPE node_filesystem_size_bytes gauge
node_filesystem_size_bytes{device="/dev/fuse",fstype="fuse",mountpoint="/run/user/1000/doc"} 0
node_filesystem_size_bytes{device="/dev/mapper/ubuntu--vg-lv_docker",fstype="ext4",mountpoint="/var/lib/docker"} 1.0434699264e+10
node_filesystem_size_bytes{device="/dev/mapper/ubuntu--vg-lv_home",fstype="ext4",mountpoint="/home"} 5.2710469632e+10
node_filesystem_size_bytes{device="/dev/mapper/ubuntu--vg-lv_libvirt",fstype="ext4",mountpoint="/var/lib/libvirt"} 5.257609216e+10
node_filesystem_size_bytes{device="/dev/mapper/ubuntu--vg-root",fstype="ext4",mountpoint="/"} 2.1003628544e+10
node_filesystem_size_bytes{device="/dev/nvme0n1p1",fstype="vfat",mountpoint="/boot/efi"} 5.35805952e+08
node_filesystem_size_bytes{device="/dev/nvme0n1p2",fstype="ext2",mountpoint="/boot"} 2.4777216e+08
node_filesystem_size_bytes{device="gvfsd-fuse",fstype="fuse.gvfsd-fuse",mountpoint="/run/user/1000/gvfs"} 0
node_filesystem_size_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run"} 1.567645696e+09
node_filesystem_size_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run/lock"} 5.24288e+06
node_filesystem_size_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run/snapd/ns"} 1.567645696e+09
node_filesystem_size_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run/user/1000"} 1.5676416e+09
node_filesystem_size_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run/user/1001"} 1.5676416e+09
# HELP node_forks_total Total number of forks.
# TYPE node_forks_total counter
node_forks_total 132851
# HELP node_hwmon_chip_names Annotation metric for human-readable chip names
# TYPE node_hwmon_chip_names gauge
node_hwmon_chip_names{chip="platform_coretemp_0",chip_name="coretemp"} 1
node_hwmon_chip_names{chip="thermal_thermal_zone0",chip_name="acpitz"} 1
# HELP node_hwmon_sensor_label Label for given chip and sensor
# TYPE node_hwmon_sensor_label gauge
node_hwmon_sensor_label{chip="platform_coretemp_0",label="core_0",sensor="temp2"} 1
node_hwmon_sensor_label{chip="platform_coretemp_0",label="core_1",sensor="temp3"} 1
node_hwmon_sensor_label{chip="platform_coretemp_0",label="core_2",sensor="temp4"} 1
node_hwmon_sensor_label{chip="platform_coretemp_0",label="core_3",sensor="temp5"} 1
node_hwmon_sensor_label{chip="platform_coretemp_0",label="package_id_0",sensor="temp1"} 1
# HELP node_hwmon_temp_celsius Hardware monitor for temperature (input)
# TYPE node_hwmon_temp_celsius gauge
node_hwmon_temp_celsius{chip="platform_coretemp_0",sensor="temp1"} 25
node_hwmon_temp_celsius{chip="platform_coretemp_0",sensor="temp2"} 21
node_hwmon_temp_celsius{chip="platform_coretemp_0",sensor="temp3"} 25
node_hwmon_temp_celsius{chip="platform_coretemp_0",sensor="temp4"} 22
node_hwmon_temp_celsius{chip="platform_coretemp_0",sensor="temp5"} 21
node_hwmon_temp_celsius{chip="thermal_thermal_zone0",sensor="temp0"} 27.8
node_hwmon_temp_celsius{chip="thermal_thermal_zone0",sensor="temp1"} 27.8
node_hwmon_temp_celsius{chip="thermal_thermal_zone0",sensor="temp2"} 29.8
# HELP node_hwmon_temp_crit_alarm_celsius Hardware monitor for temperature (crit_alarm)
# TYPE node_hwmon_temp_crit_alarm_celsius gauge
node_hwmon_temp_crit_alarm_celsius{chip="platform_coretemp_0",sensor="temp1"} 0
node_hwmon_temp_crit_alarm_celsius{chip="platform_coretemp_0",sensor="temp2"} 0
node_hwmon_temp_crit_alarm_celsius{chip="platform_coretemp_0",sensor="temp3"} 0
node_hwmon_temp_crit_alarm_celsius{chip="platform_coretemp_0",sensor="temp4"} 0
node_hwmon_temp_crit_alarm_celsius{chip="platform_coretemp_0",sensor="temp5"} 0
# HELP node_hwmon_temp_crit_celsius Hardware monitor for temperature (crit)
# TYPE node_hwmon_temp_crit_celsius gauge
node_hwmon_temp_crit_celsius{chip="platform_coretemp_0",sensor="temp1"} 100
node_hwmon_temp_crit_celsius{chip="platform_coretemp_0",sensor="temp2"} 100
node_hwmon_temp_crit_celsius{chip="platform_coretemp_0",sensor="temp3"} 100
node_hwmon_temp_crit_celsius{chip="platform_coretemp_0",sensor="temp4"} 100
node_hwmon_temp_crit_celsius{chip="platform_coretemp_0",sensor="temp5"} 100
node_hwmon_temp_crit_celsius{chip="thermal_thermal_zone0",sensor="temp1"} 119
node_hwmon_temp_crit_celsius{chip="thermal_thermal_zone0",sensor="temp2"} 119
# HELP node_hwmon_temp_max_celsius Hardware monitor for temperature (max)
# TYPE node_hwmon_temp_max_celsius gauge
node_hwmon_temp_max_celsius{chip="platform_coretemp_0",sensor="temp1"} 84
node_hwmon_temp_max_celsius{chip="platform_coretemp_0",sensor="temp2"} 84
node_hwmon_temp_max_celsius{chip="platform_coretemp_0",sensor="temp3"} 84
node_hwmon_temp_max_celsius{chip="platform_coretemp_0",sensor="temp4"} 84
node_hwmon_temp_max_celsius{chip="platform_coretemp_0",sensor="temp5"} 84
# HELP node_intr_total Total number of interrupts serviced.
# TYPE node_intr_total counter
node_intr_total 4.1192445e+07
# HELP node_load1 1m load average.
# TYPE node_load1 gauge
node_load1 0.04
# HELP node_load15 15m load average.
# TYPE node_load15 gauge
node_load15 0.05
# HELP node_load5 5m load average.
# TYPE node_load5 gauge
node_load5 0.03
# HELP node_memory_Active_anon_bytes Memory information field Active_anon_bytes.
# TYPE node_memory_Active_anon_bytes gauge
node_memory_Active_anon_bytes 6.44501504e+09
# HELP node_memory_Active_bytes Memory information field Active_bytes.
# TYPE node_memory_Active_bytes gauge
node_memory_Active_bytes 9.42606336e+09
# HELP node_memory_Active_file_bytes Memory information field Active_file_bytes.
# TYPE node_memory_Active_file_bytes gauge
node_memory_Active_file_bytes 2.98104832e+09
# HELP node_memory_AnonHugePages_bytes Memory information field AnonHugePages_bytes.
# TYPE node_memory_AnonHugePages_bytes gauge
node_memory_AnonHugePages_bytes 1.2582912e+07
# HELP node_memory_AnonPages_bytes Memory information field AnonPages_bytes.
# TYPE node_memory_AnonPages_bytes gauge
node_memory_AnonPages_bytes 6.969450496e+09
# HELP node_memory_Bounce_bytes Memory information field Bounce_bytes.
# TYPE node_memory_Bounce_bytes gauge
node_memory_Bounce_bytes 0
# HELP node_memory_Buffers_bytes Memory information field Buffers_bytes.
# TYPE node_memory_Buffers_bytes gauge
node_memory_Buffers_bytes 1.110511616e+09
# HELP node_memory_Cached_bytes Memory information field Cached_bytes.
# TYPE node_memory_Cached_bytes gauge
node_memory_Cached_bytes 4.934221824e+09
# HELP node_memory_CmaFree_bytes Memory information field CmaFree_bytes.
# TYPE node_memory_CmaFree_bytes gauge
node_memory_CmaFree_bytes 0
# HELP node_memory_CmaTotal_bytes Memory information field CmaTotal_bytes.
# TYPE node_memory_CmaTotal_bytes gauge
node_memory_CmaTotal_bytes 0
# HELP node_memory_CommitLimit_bytes Memory information field CommitLimit_bytes.
# TYPE node_memory_CommitLimit_bytes gauge
node_memory_CommitLimit_bytes 2.4892243968e+10
# HELP node_memory_Committed_AS_bytes Memory information field Committed_AS_bytes.
# TYPE node_memory_Committed_AS_bytes gauge
node_memory_Committed_AS_bytes 2.16594432e+10
# HELP node_memory_DirectMap1G_bytes Memory information field DirectMap1G_bytes.
# TYPE node_memory_DirectMap1G_bytes gauge
node_memory_DirectMap1G_bytes 1.073741824e+09
# HELP node_memory_DirectMap2M_bytes Memory information field DirectMap2M_bytes.
# TYPE node_memory_DirectMap2M_bytes gauge
node_memory_DirectMap2M_bytes 1.4508097536e+10
# HELP node_memory_DirectMap4k_bytes Memory information field DirectMap4k_bytes.
# TYPE node_memory_DirectMap4k_bytes gauge
node_memory_DirectMap4k_bytes 4.66436096e+08
# HELP node_memory_Dirty_bytes Memory information field Dirty_bytes.
# TYPE node_memory_Dirty_bytes gauge
node_memory_Dirty_bytes 131072
# HELP node_memory_HardwareCorrupted_bytes Memory information field HardwareCorrupted_bytes.
# TYPE node_memory_HardwareCorrupted_bytes gauge
node_memory_HardwareCorrupted_bytes 0
# HELP node_memory_HugePages_Free Memory information field HugePages_Free.
# TYPE node_memory_HugePages_Free gauge
node_memory_HugePages_Free 0
# HELP node_memory_HugePages_Rsvd Memory information field HugePages_Rsvd.
# TYPE node_memory_HugePages_Rsvd gauge
node_memory_HugePages_Rsvd 0
# HELP node_memory_HugePages_Surp Memory information field HugePages_Surp.
# TYPE node_memory_HugePages_Surp gauge
node_memory_HugePages_Surp 0
# HELP node_memory_HugePages_Total Memory information field HugePages_Total.
# TYPE node_memory_HugePages_Total gauge
node_memory_HugePages_Total 0
# HELP node_memory_Hugepagesize_bytes Memory information field Hugepagesize_bytes.
# TYPE node_memory_Hugepagesize_bytes gauge
node_memory_Hugepagesize_bytes 2.097152e+06
# HELP node_memory_Hugetlb_bytes Memory information field Hugetlb_bytes.
# TYPE node_memory_Hugetlb_bytes gauge
node_memory_Hugetlb_bytes 0
# HELP node_memory_Inactive_anon_bytes Memory information field Inactive_anon_bytes.
# TYPE node_memory_Inactive_anon_bytes gauge
node_memory_Inactive_anon_bytes 1.221947392e+09
# HELP node_memory_Inactive_bytes Memory information field Inactive_bytes.
# TYPE node_memory_Inactive_bytes gauge
node_memory_Inactive_bytes 3.794579456e+09
# HELP node_memory_Inactive_file_bytes Memory information field Inactive_file_bytes.
# TYPE node_memory_Inactive_file_bytes gauge
node_memory_Inactive_file_bytes 2.572632064e+09
# HELP node_memory_KReclaimable_bytes Memory information field KReclaimable_bytes.
# TYPE node_memory_KReclaimable_bytes gauge
node_memory_KReclaimable_bytes 6.1536256e+08
# HELP node_memory_KernelStack_bytes Memory information field KernelStack_bytes.
# TYPE node_memory_KernelStack_bytes gauge
node_memory_KernelStack_bytes 2.6722304e+07
# HELP node_memory_Mapped_bytes Memory information field Mapped_bytes.
# TYPE node_memory_Mapped_bytes gauge
node_memory_Mapped_bytes 1.37148416e+09
# HELP node_memory_MemAvailable_bytes Memory information field MemAvailable_bytes.
# TYPE node_memory_MemAvailable_bytes gauge
node_memory_MemAvailable_bytes 7.02457856e+09
# HELP node_memory_MemFree_bytes Memory information field MemFree_bytes.
# TYPE node_memory_MemFree_bytes gauge
node_memory_MemFree_bytes 1.239457792e+09
# HELP node_memory_MemTotal_bytes Memory information field MemTotal_bytes.
# TYPE node_memory_MemTotal_bytes gauge
node_memory_MemTotal_bytes 1.5676420096e+10
# HELP node_memory_Mlocked_bytes Memory information field Mlocked_bytes.
# TYPE node_memory_Mlocked_bytes gauge
node_memory_Mlocked_bytes 180224
# HELP node_memory_NFS_Unstable_bytes Memory information field NFS_Unstable_bytes.
# TYPE node_memory_NFS_Unstable_bytes gauge
node_memory_NFS_Unstable_bytes 0
# HELP node_memory_PageTables_bytes Memory information field PageTables_bytes.
# TYPE node_memory_PageTables_bytes gauge
node_memory_PageTables_bytes 9.2131328e+07
# HELP node_memory_Percpu_bytes Memory information field Percpu_bytes.
# TYPE node_memory_Percpu_bytes gauge
node_memory_Percpu_bytes 4.521984e+06
# HELP node_memory_SReclaimable_bytes Memory information field SReclaimable_bytes.
# TYPE node_memory_SReclaimable_bytes gauge
node_memory_SReclaimable_bytes 6.1536256e+08
# HELP node_memory_SUnreclaim_bytes Memory information field SUnreclaim_bytes.
# TYPE node_memory_SUnreclaim_bytes gauge
node_memory_SUnreclaim_bytes 1.86236928e+08
# HELP node_memory_ShmemHugePages_bytes Memory information field ShmemHugePages_bytes.
# TYPE node_memory_ShmemHugePages_bytes gauge
node_memory_ShmemHugePages_bytes 0
# HELP node_memory_ShmemPmdMapped_bytes Memory information field ShmemPmdMapped_bytes.
# TYPE node_memory_ShmemPmdMapped_bytes gauge
node_memory_ShmemPmdMapped_bytes 0
# HELP node_memory_Shmem_bytes Memory information field Shmem_bytes.
# TYPE node_memory_Shmem_bytes gauge
node_memory_Shmem_bytes 8.27334656e+08
# HELP node_memory_Slab_bytes Memory information field Slab_bytes.
# TYPE node_memory_Slab_bytes gauge
node_memory_Slab_bytes 8.01599488e+08
# HELP node_memory_SwapCached_bytes Memory information field SwapCached_bytes.
# TYPE node_memory_SwapCached_bytes gauge
node_memory_SwapCached_bytes 3.88194304e+08
# HELP node_memory_SwapFree_bytes Memory information field SwapFree_bytes.
# TYPE node_memory_SwapFree_bytes gauge
node_memory_SwapFree_bytes 1.6662392832e+10
# HELP node_memory_SwapTotal_bytes Memory information field SwapTotal_bytes.
# TYPE node_memory_SwapTotal_bytes gauge
node_memory_SwapTotal_bytes 1.7054035968e+10
# HELP node_memory_Unevictable_bytes Memory information field Unevictable_bytes.
# TYPE node_memory_Unevictable_bytes gauge
node_memory_Unevictable_bytes 1.8167808e+08
# HELP node_memory_VmallocChunk_bytes Memory information field VmallocChunk_bytes.
# TYPE node_memory_VmallocChunk_bytes gauge
node_memory_VmallocChunk_bytes 0
# HELP node_memory_VmallocTotal_bytes Memory information field VmallocTotal_bytes.
# TYPE node_memory_VmallocTotal_bytes gauge
node_memory_VmallocTotal_bytes 3.5184372087808e+13
# HELP node_memory_VmallocUsed_bytes Memory information field VmallocUsed_bytes.
# TYPE node_memory_VmallocUsed_bytes gauge
node_memory_VmallocUsed_bytes 4.7013888e+07
# HELP node_memory_WritebackTmp_bytes Memory information field WritebackTmp_bytes.
# TYPE node_memory_WritebackTmp_bytes gauge
node_memory_WritebackTmp_bytes 0
# HELP node_memory_Writeback_bytes Memory information field Writeback_bytes.
# TYPE node_memory_Writeback_bytes gauge
node_memory_Writeback_bytes 0
# HELP node_netstat_Icmp6_InErrors Statistic Icmp6InErrors.
# TYPE node_netstat_Icmp6_InErrors untyped
node_netstat_Icmp6_InErrors 0
# HELP node_netstat_Icmp6_InMsgs Statistic Icmp6InMsgs.
# TYPE node_netstat_Icmp6_InMsgs untyped
node_netstat_Icmp6_InMsgs 295
# HELP node_netstat_Icmp6_OutMsgs Statistic Icmp6OutMsgs.
# TYPE node_netstat_Icmp6_OutMsgs untyped
node_netstat_Icmp6_OutMsgs 460
# HELP node_netstat_Icmp_InErrors Statistic IcmpInErrors.
# TYPE node_netstat_Icmp_InErrors untyped
node_netstat_Icmp_InErrors 0
# HELP node_netstat_Icmp_InMsgs Statistic IcmpInMsgs.
# TYPE node_netstat_Icmp_InMsgs untyped
node_netstat_Icmp_InMsgs 46
# HELP node_netstat_Icmp_OutMsgs Statistic IcmpOutMsgs.
# TYPE node_netstat_Icmp_OutMsgs untyped
node_netstat_Icmp_OutMsgs 111
# HELP node_netstat_Ip6_InOctets Statistic Ip6InOctets.
# TYPE node_netstat_Ip6_InOctets untyped
node_netstat_Ip6_InOctets 3.02500642e+08
# HELP node_netstat_Ip6_OutOctets Statistic Ip6OutOctets.
# TYPE node_netstat_Ip6_OutOctets untyped
node_netstat_Ip6_OutOctets 2.9211487e+07
# HELP node_netstat_IpExt_InOctets Statistic IpExtInOctets.
# TYPE node_netstat_IpExt_InOctets untyped
node_netstat_IpExt_InOctets 2.532358795e+09
# HELP node_netstat_IpExt_OutOctets Statistic IpExtOutOctets.
# TYPE node_netstat_IpExt_OutOctets untyped
node_netstat_IpExt_OutOctets 1.04651471e+08
# HELP node_netstat_Ip_Forwarding Statistic IpForwarding.
# TYPE node_netstat_Ip_Forwarding untyped
node_netstat_Ip_Forwarding 1
# HELP node_netstat_TcpExt_ListenDrops Statistic TcpExtListenDrops.
# TYPE node_netstat_TcpExt_ListenDrops untyped
node_netstat_TcpExt_ListenDrops 0
# HELP node_netstat_TcpExt_ListenOverflows Statistic TcpExtListenOverflows.
# TYPE node_netstat_TcpExt_ListenOverflows untyped
node_netstat_TcpExt_ListenOverflows 0
# HELP node_netstat_TcpExt_SyncookiesFailed Statistic TcpExtSyncookiesFailed.
# TYPE node_netstat_TcpExt_SyncookiesFailed untyped
node_netstat_TcpExt_SyncookiesFailed 0
# HELP node_netstat_TcpExt_SyncookiesRecv Statistic TcpExtSyncookiesRecv.
# TYPE node_netstat_TcpExt_SyncookiesRecv untyped
node_netstat_TcpExt_SyncookiesRecv 0
# HELP node_netstat_TcpExt_SyncookiesSent Statistic TcpExtSyncookiesSent.
# TYPE node_netstat_TcpExt_SyncookiesSent untyped
node_netstat_TcpExt_SyncookiesSent 0
# HELP node_netstat_TcpExt_TCPSynRetrans Statistic TcpExtTCPSynRetrans.
# TYPE node_netstat_TcpExt_TCPSynRetrans untyped
node_netstat_TcpExt_TCPSynRetrans 580
# HELP node_netstat_Tcp_ActiveOpens Statistic TcpActiveOpens.
# TYPE node_netstat_Tcp_ActiveOpens untyped
node_netstat_Tcp_ActiveOpens 57274
# HELP node_netstat_Tcp_CurrEstab Statistic TcpCurrEstab.
# TYPE node_netstat_Tcp_CurrEstab untyped
node_netstat_Tcp_CurrEstab 24
# HELP node_netstat_Tcp_InErrs Statistic TcpInErrs.
# TYPE node_netstat_Tcp_InErrs untyped
node_netstat_Tcp_InErrs 4
# HELP node_netstat_Tcp_InSegs Statistic TcpInSegs.
# TYPE node_netstat_Tcp_InSegs untyped
node_netstat_Tcp_InSegs 2.195316e+06
# HELP node_netstat_Tcp_OutSegs Statistic TcpOutSegs.
# TYPE node_netstat_Tcp_OutSegs untyped
node_netstat_Tcp_OutSegs 1.246388e+06
# HELP node_netstat_Tcp_PassiveOpens Statistic TcpPassiveOpens.
# TYPE node_netstat_Tcp_PassiveOpens untyped
node_netstat_Tcp_PassiveOpens 90
# HELP node_netstat_Tcp_RetransSegs Statistic TcpRetransSegs.
# TYPE node_netstat_Tcp_RetransSegs untyped
node_netstat_Tcp_RetransSegs 677
# HELP node_netstat_Udp6_InDatagrams Statistic Udp6InDatagrams.
# TYPE node_netstat_Udp6_InDatagrams untyped
node_netstat_Udp6_InDatagrams 3203
# HELP node_netstat_Udp6_InErrors Statistic Udp6InErrors.
# TYPE node_netstat_Udp6_InErrors untyped
node_netstat_Udp6_InErrors 0
# HELP node_netstat_Udp6_NoPorts Statistic Udp6NoPorts.
# TYPE node_netstat_Udp6_NoPorts untyped
node_netstat_Udp6_NoPorts 0
# HELP node_netstat_Udp6_OutDatagrams Statistic Udp6OutDatagrams.
# TYPE node_netstat_Udp6_OutDatagrams untyped
node_netstat_Udp6_OutDatagrams 2528
# HELP node_netstat_Udp6_RcvbufErrors Statistic Udp6RcvbufErrors.
# TYPE node_netstat_Udp6_RcvbufErrors untyped
node_netstat_Udp6_RcvbufErrors 0
# HELP node_netstat_Udp6_SndbufErrors Statistic Udp6SndbufErrors.
# TYPE node_netstat_Udp6_SndbufErrors untyped
node_netstat_Udp6_SndbufErrors 0
# HELP node_netstat_UdpLite6_InErrors Statistic UdpLite6InErrors.
# TYPE node_netstat_UdpLite6_InErrors untyped
node_netstat_UdpLite6_InErrors 0
# HELP node_netstat_UdpLite_InErrors Statistic UdpLiteInErrors.
# TYPE node_netstat_UdpLite_InErrors untyped
node_netstat_UdpLite_InErrors 0
# HELP node_netstat_Udp_InDatagrams Statistic UdpInDatagrams.
# TYPE node_netstat_Udp_InDatagrams untyped
node_netstat_Udp_InDatagrams 55971
# HELP node_netstat_Udp_InErrors Statistic UdpInErrors.
# TYPE node_netstat_Udp_InErrors untyped
node_netstat_Udp_InErrors 0
# HELP node_netstat_Udp_NoPorts Statistic UdpNoPorts.
# TYPE node_netstat_Udp_NoPorts untyped
node_netstat_Udp_NoPorts 46
# HELP node_netstat_Udp_OutDatagrams Statistic UdpOutDatagrams.
# TYPE node_netstat_Udp_OutDatagrams untyped
node_netstat_Udp_OutDatagrams 56879
# HELP node_netstat_Udp_RcvbufErrors Statistic UdpRcvbufErrors.
# TYPE node_netstat_Udp_RcvbufErrors untyped
node_netstat_Udp_RcvbufErrors 0
# HELP node_netstat_Udp_SndbufErrors Statistic UdpSndbufErrors.
# TYPE node_netstat_Udp_SndbufErrors untyped
node_netstat_Udp_SndbufErrors 0
# HELP node_network_address_assign_type address_assign_type value of /sys/class/net/<iface>.
# TYPE node_network_address_assign_type gauge
node_network_address_assign_type{device="docker0"} 3
node_network_address_assign_type{device="enp0s31f6"} 0
node_network_address_assign_type{device="lo"} 0
node_network_address_assign_type{device="virbr0"} 1
node_network_address_assign_type{device="virbr0-nic"} 3
node_network_address_assign_type{device="wg0"} 0
# HELP node_network_carrier carrier value of /sys/class/net/<iface>.
# TYPE node_network_carrier gauge
node_network_carrier{device="docker0"} 0
node_network_carrier{device="enp0s31f6"} 1
node_network_carrier{device="lo"} 1
node_network_carrier{device="virbr0"} 0
node_network_carrier{device="wg0"} 1
# HELP node_network_carrier_changes_total carrier_changes_total value of /sys/class/net/<iface>.
# TYPE node_network_carrier_changes_total counter
node_network_carrier_changes_total{device="docker0"} 11
node_network_carrier_changes_total{device="enp0s31f6"} 2
node_network_carrier_changes_total{device="lo"} 0
node_network_carrier_changes_total{device="virbr0"} 1
node_network_carrier_changes_total{device="virbr0-nic"} 1
node_network_carrier_changes_total{device="wg0"} 0
# HELP node_network_carrier_down_changes_total carrier_down_changes_total value of /sys/class/net/<iface>.
# TYPE node_network_carrier_down_changes_total counter
node_network_carrier_down_changes_total{device="docker0"} 6
node_network_carrier_down_changes_total{device="enp0s31f6"} 1
node_network_carrier_down_changes_total{device="lo"} 0
node_network_carrier_down_changes_total{device="virbr0"} 1
node_network_carrier_down_changes_total{device="virbr0-nic"} 1
node_network_carrier_down_changes_total{device="wg0"} 0
# HELP node_network_carrier_up_changes_total carrier_up_changes_total value of /sys/class/net/<iface>.
# TYPE node_network_carrier_up_changes_total counter
node_network_carrier_up_changes_total{device="docker0"} 5
node_network_carrier_up_changes_total{device="enp0s31f6"} 1
node_network_carrier_up_changes_total{device="lo"} 0
node_network_carrier_up_changes_total{device="virbr0"} 0
node_network_carrier_up_changes_total{device="virbr0-nic"} 0
node_network_carrier_up_changes_total{device="wg0"} 0
# HELP node_network_device_id device_id value of /sys/class/net/<iface>.
# TYPE node_network_device_id gauge
node_network_device_id{device="docker0"} 0
node_network_device_id{device="enp0s31f6"} 0
node_network_device_id{device="lo"} 0
node_network_device_id{device="virbr0"} 0
node_network_device_id{device="virbr0-nic"} 0
node_network_device_id{device="wg0"} 0
# HELP node_network_dormant dormant value of /sys/class/net/<iface>.
# TYPE node_network_dormant gauge
node_network_dormant{device="docker0"} 0
node_network_dormant{device="enp0s31f6"} 0
node_network_dormant{device="lo"} 0
node_network_dormant{device="virbr0"} 0
node_network_dormant{device="wg0"} 0
# HELP node_network_flags flags value of /sys/class/net/<iface>.
# TYPE node_network_flags gauge
node_network_flags{device="docker0"} 4099
node_network_flags{device="enp0s31f6"} 4099
node_network_flags{device="lo"} 9
node_network_flags{device="virbr0"} 4099
node_network_flags{device="virbr0-nic"} 4866
node_network_flags{device="wg0"} 4241
# HELP node_network_iface_id iface_id value of /sys/class/net/<iface>.
# TYPE node_network_iface_id gauge
node_network_iface_id{device="docker0"} 6
node_network_iface_id{device="enp0s31f6"} 2
node_network_iface_id{device="lo"} 1
node_network_iface_id{device="virbr0"} 4
node_network_iface_id{device="virbr0-nic"} 5
node_network_iface_id{device="wg0"} 3
# HELP node_network_iface_link iface_link value of /sys/class/net/<iface>.
# TYPE node_network_iface_link gauge
node_network_iface_link{device="docker0"} 6
node_network_iface_link{device="enp0s31f6"} 2
node_network_iface_link{device="lo"} 1
node_network_iface_link{device="virbr0"} 4
node_network_iface_link{device="virbr0-nic"} 5
node_network_iface_link{device="wg0"} 3
# HELP node_network_iface_link_mode iface_link_mode value of /sys/class/net/<iface>.
# TYPE node_network_iface_link_mode gauge
node_network_iface_link_mode{device="docker0"} 0
node_network_iface_link_mode{device="enp0s31f6"} 0
node_network_iface_link_mode{device="lo"} 0
node_network_iface_link_mode{device="virbr0"} 0
node_network_iface_link_mode{device="virbr0-nic"} 0
node_network_iface_link_mode{device="wg0"} 0
# HELP node_network_info Non-numeric data from /sys/class/net/<iface>, value is always 1.
# TYPE node_network_info gauge
node_network_info{address="",broadcast="",device="wg0",duplex="full",ifalias="",operstate="unknown"} 1
node_network_info{address="00:00:00:00:00:00",broadcast="00:00:00:00:00:00",device="lo",duplex="",ifalias="",operstate="unknown"} 1
node_network_info{address="02:42:31:f8:52:2a",broadcast="ff:ff:ff:ff:ff:ff",device="docker0",duplex="",ifalias="",operstate="down"} 1
node_network_info{address="40:8d:5c:5d:1e:b7",broadcast="ff:ff:ff:ff:ff:ff",device="enp0s31f6",duplex="full",ifalias="",operstate="up"} 1
node_network_info{address="52:54:00:01:78:4c",broadcast="ff:ff:ff:ff:ff:ff",device="virbr0",duplex="",ifalias="",operstate="down"} 1
node_network_info{address="52:54:00:01:78:4c",broadcast="ff:ff:ff:ff:ff:ff",device="virbr0-nic",duplex="",ifalias="",operstate="down"} 1
# HELP node_network_mtu_bytes mtu_bytes value of /sys/class/net/<iface>.
# TYPE node_network_mtu_bytes gauge
node_network_mtu_bytes{device="docker0"} 1500
node_network_mtu_bytes{device="enp0s31f6"} 1500
node_network_mtu_bytes{device="lo"} 65536
node_network_mtu_bytes{device="virbr0"} 1500
node_network_mtu_bytes{device="virbr0-nic"} 1500
node_network_mtu_bytes{device="wg0"} 1420
# HELP node_network_name_assign_type name_assign_type value of /sys/class/net/<iface>.
# TYPE node_network_name_assign_type gauge
node_network_name_assign_type{device="docker0"} 3
node_network_name_assign_type{device="enp0s31f6"} 4
node_network_name_assign_type{device="virbr0"} 3
# HELP node_network_net_dev_group net_dev_group value of /sys/class/net/<iface>.
# TYPE node_network_net_dev_group gauge
node_network_net_dev_group{device="docker0"} 0
node_network_net_dev_group{device="enp0s31f6"} 0
node_network_net_dev_group{device="lo"} 0
node_network_net_dev_group{device="virbr0"} 0
node_network_net_dev_group{device="virbr0-nic"} 0
node_network_net_dev_group{device="wg0"} 0
# HELP node_network_protocol_type protocol_type value of /sys/class/net/<iface>.
# TYPE node_network_protocol_type gauge
node_network_protocol_type{device="docker0"} 1
node_network_protocol_type{device="enp0s31f6"} 1
node_network_protocol_type{device="lo"} 772
node_network_protocol_type{device="virbr0"} 1
node_network_protocol_type{device="virbr0-nic"} 1
node_network_protocol_type{device="wg0"} 65534
# HELP node_network_receive_bytes_total Network device statistic receive_bytes.
# TYPE node_network_receive_bytes_total counter
node_network_receive_bytes_total{device="docker0"} 262961
node_network_receive_bytes_total{device="enp0s31f6"} 2.865461055e+09
node_network_receive_bytes_total{device="lo"} 1.1229763e+07
node_network_receive_bytes_total{device="virbr0"} 0
node_network_receive_bytes_total{device="virbr0-nic"} 0
node_network_receive_bytes_total{device="wg0"} 0
# HELP node_network_receive_compressed_total Network device statistic receive_compressed.
# TYPE node_network_receive_compressed_total counter
node_network_receive_compressed_total{device="docker0"} 0
node_network_receive_compressed_total{device="enp0s31f6"} 0
node_network_receive_compressed_total{device="lo"} 0
node_network_receive_compressed_total{device="virbr0"} 0
node_network_receive_compressed_total{device="virbr0-nic"} 0
node_network_receive_compressed_total{device="wg0"} 0
# HELP node_network_receive_drop_total Network device statistic receive_drop.
# TYPE node_network_receive_drop_total counter
node_network_receive_drop_total{device="docker0"} 0
node_network_receive_drop_total{device="enp0s31f6"} 41921
node_network_receive_drop_total{device="lo"} 0
node_network_receive_drop_total{device="virbr0"} 0
node_network_receive_drop_total{device="virbr0-nic"} 0
node_network_receive_drop_total{device="wg0"} 0
# HELP node_network_receive_errs_total Network device statistic receive_errs.
# TYPE node_network_receive_errs_total counter
node_network_receive_errs_total{device="docker0"} 0
node_network_receive_errs_total{device="enp0s31f6"} 0
node_network_receive_errs_total{device="lo"} 0
node_network_receive_errs_total{device="virbr0"} 0
node_network_receive_errs_total{device="virbr0-nic"} 0
node_network_receive_errs_total{device="wg0"} 0
# HELP node_network_receive_fifo_total Network device statistic receive_fifo.
# TYPE node_network_receive_fifo_total counter
node_network_receive_fifo_total{device="docker0"} 0
node_network_receive_fifo_total{device="enp0s31f6"} 0
node_network_receive_fifo_total{device="lo"} 0
node_network_receive_fifo_total{device="virbr0"} 0
node_network_receive_fifo_total{device="virbr0-nic"} 0
node_network_receive_fifo_total{device="wg0"} 0
# HELP node_network_receive_frame_total Network device statistic receive_frame.
# TYPE node_network_receive_frame_total counter
node_network_receive_frame_total{device="docker0"} 0
node_network_receive_frame_total{device="enp0s31f6"} 0
node_network_receive_frame_total{device="lo"} 0
node_network_receive_frame_total{device="virbr0"} 0
node_network_receive_frame_total{device="virbr0-nic"} 0
node_network_receive_frame_total{device="wg0"} 0
# HELP node_network_receive_multicast_total Network device statistic receive_multicast.
# TYPE node_network_receive_multicast_total counter
node_network_receive_multicast_total{device="docker0"} 0
node_network_receive_multicast_total{device="enp0s31f6"} 13665
node_network_receive_multicast_total{device="lo"} 0
node_network_receive_multicast_total{device="virbr0"} 0
node_network_receive_multicast_total{device="virbr0-nic"} 0
node_network_receive_multicast_total{device="wg0"} 0
# HELP node_network_receive_packets_total Network device statistic receive_packets.
# TYPE node_network_receive_packets_total counter
node_network_receive_packets_total{device="docker0"} 5037
node_network_receive_packets_total{device="enp0s31f6"} 2.190458e+06
node_network_receive_packets_total{device="lo"} 141131
node_network_receive_packets_total{device="virbr0"} 0
node_network_receive_packets_total{device="virbr0-nic"} 0
node_network_receive_packets_total{device="wg0"} 0
# HELP node_network_speed_bytes speed_bytes value of /sys/class/net/<iface>.
# TYPE node_network_speed_bytes gauge
node_network_speed_bytes{device="enp0s31f6"} 1.25e+08
node_network_speed_bytes{device="wg0"} 1.25e+06
# HELP node_network_transmit_bytes_total Network device statistic transmit_bytes.
# TYPE node_network_transmit_bytes_total counter
node_network_transmit_bytes_total{device="docker0"} 1.2775698e+07
node_network_transmit_bytes_total{device="enp0s31f6"} 1.18303491e+08
node_network_transmit_bytes_total{device="lo"} 1.1229763e+07
node_network_transmit_bytes_total{device="virbr0"} 0
node_network_transmit_bytes_total{device="virbr0-nic"} 0
node_network_transmit_bytes_total{device="wg0"} 254760
# HELP node_network_transmit_carrier_total Network device statistic transmit_carrier.
# TYPE node_network_transmit_carrier_total counter
node_network_transmit_carrier_total{device="docker0"} 0
node_network_transmit_carrier_total{device="enp0s31f6"} 0
node_network_transmit_carrier_total{device="lo"} 0
node_network_transmit_carrier_total{device="virbr0"} 0
node_network_transmit_carrier_total{device="virbr0-nic"} 0
node_network_transmit_carrier_total{device="wg0"} 0
# HELP node_network_transmit_colls_total Network device statistic transmit_colls.
# TYPE node_network_transmit_colls_total counter
node_network_transmit_colls_total{device="docker0"} 0
node_network_transmit_colls_total{device="enp0s31f6"} 0
node_network_transmit_colls_total{device="lo"} 0
node_network_transmit_colls_total{device="virbr0"} 0
node_network_transmit_colls_total{device="virbr0-nic"} 0
node_network_transmit_colls_total{device="wg0"} 0
# HELP node_network_transmit_compressed_total Network device statistic transmit_compressed.
# TYPE node_network_transmit_compressed_total counter
node_network_transmit_compressed_total{device="docker0"} 0
node_network_transmit_compressed_total{device="enp0s31f6"} 0
node_network_transmit_compressed_total{device="lo"} 0
node_network_transmit_compressed_total{device="virbr0"} 0
node_network_transmit_compressed_total{device="virbr0-nic"} 0
node_network_transmit_compressed_total{device="wg0"} 0
# HELP node_network_transmit_drop_total Network device statistic transmit_drop.
# TYPE node_network_transmit_drop_total counter
node_network_transmit_drop_total{device="docker0"} 0
node_network_transmit_drop_total{device="enp0s31f6"} 0
node_network_transmit_drop_total{device="lo"} 0
node_network_transmit_drop_total{device="virbr0"} 0
node_network_transmit_drop_total{device="virbr0-nic"} 0
node_network_transmit_drop_total{device="wg0"} 0
# HELP node_network_transmit_errs_total Network device statistic transmit_errs.
# TYPE node_network_transmit_errs_total counter
node_network_transmit_errs_total{device="docker0"} 0
node_network_transmit_errs_total{device="enp0s31f6"} 0
node_network_transmit_errs_total{device="lo"} 0
node_network_transmit_errs_total{device="virbr0"} 0
node_network_transmit_errs_total{device="virbr0-nic"} 0
node_network_transmit_errs_total{device="wg0"} 0
# HELP node_network_transmit_fifo_total Network device statistic transmit_fifo.
# TYPE node_network_transmit_fifo_total counter
node_network_transmit_fifo_total{device="docker0"} 0
node_network_transmit_fifo_total{device="enp0s31f6"} 0
node_network_transmit_fifo_total{device="lo"} 0
node_network_transmit_fifo_total{device="virbr0"} 0
node_network_transmit_fifo_total{device="virbr0-nic"} 0
node_network_transmit_fifo_total{device="wg0"} 0
# HELP node_network_transmit_packets_total Network device statistic transmit_packets.
# TYPE node_network_transmit_packets_total counter
node_network_transmit_packets_total{device="docker0"} 9359
node_network_transmit_packets_total{device="enp0s31f6"} 1.170227e+06
node_network_transmit_packets_total{device="lo"} 141131
node_network_transmit_packets_total{device="virbr0"} 0
node_network_transmit_packets_total{device="virbr0-nic"} 0
node_network_transmit_packets_total{device="wg0"} 1838
# HELP node_network_transmit_queue_length transmit_queue_length value of /sys/class/net/<iface>.
# TYPE node_network_transmit_queue_length gauge
node_network_transmit_queue_length{device="docker0"} 0
node_network_transmit_queue_length{device="enp0s31f6"} 1000
node_network_transmit_queue_length{device="lo"} 1000
node_network_transmit_queue_length{device="virbr0"} 1000
node_network_transmit_queue_length{device="virbr0-nic"} 1000
node_network_transmit_queue_length{device="wg0"} 500
# HELP node_network_up Value is 1 if operstate is 'up', 0 otherwise.
# TYPE node_network_up gauge
node_network_up{device="docker0"} 0
node_network_up{device="enp0s31f6"} 1
node_network_up{device="lo"} 0
node_network_up{device="virbr0"} 0
node_network_up{device="virbr0-nic"} 0
node_network_up{device="wg0"} 0
# HELP node_nf_conntrack_entries Number of currently allocated flow entries for connection tracking.
# TYPE node_nf_conntrack_entries gauge
node_nf_conntrack_entries 40
# HELP node_nf_conntrack_entries_limit Maximum size of connection tracking table.
# TYPE node_nf_conntrack_entries_limit gauge
node_nf_conntrack_entries_limit 262144
# HELP node_nfsd_connections_total Total number of NFSd TCP connections.
# TYPE node_nfsd_connections_total counter
node_nfsd_connections_total 0
# HELP node_nfsd_disk_bytes_read_total Total NFSd bytes read.
# TYPE node_nfsd_disk_bytes_read_total counter
node_nfsd_disk_bytes_read_total 0
# HELP node_nfsd_disk_bytes_written_total Total NFSd bytes written.
# TYPE node_nfsd_disk_bytes_written_total counter
node_nfsd_disk_bytes_written_total 0
# HELP node_nfsd_file_handles_stale_total Total number of NFSd stale file handles
# TYPE node_nfsd_file_handles_stale_total counter
node_nfsd_file_handles_stale_total 0
# HELP node_nfsd_packets_total Total NFSd network packets (sent+received) by protocol type.
# TYPE node_nfsd_packets_total counter
node_nfsd_packets_total{proto="tcp"} 0
node_nfsd_packets_total{proto="udp"} 0
# HELP node_nfsd_read_ahead_cache_not_found_total Total number of NFSd read ahead cache not found.
# TYPE node_nfsd_read_ahead_cache_not_found_total counter
node_nfsd_read_ahead_cache_not_found_total 0
# HELP node_nfsd_read_ahead_cache_size_blocks How large the read ahead cache is in blocks.
# TYPE node_nfsd_read_ahead_cache_size_blocks gauge
node_nfsd_read_ahead_cache_size_blocks 32
# HELP node_nfsd_reply_cache_hits_total Total number of NFSd Reply Cache hits (client lost server response).
# TYPE node_nfsd_reply_cache_hits_total counter
node_nfsd_reply_cache_hits_total 0
# HELP node_nfsd_reply_cache_misses_total Total number of NFSd Reply Cache an operation that requires caching (idempotent).
# TYPE node_nfsd_reply_cache_misses_total counter
node_nfsd_reply_cache_misses_total 0
# HELP node_nfsd_reply_cache_nocache_total Total number of NFSd Reply Cache non-idempotent operations (rename/delete/…).
# TYPE node_nfsd_reply_cache_nocache_total counter
node_nfsd_reply_cache_nocache_total 0
# HELP node_nfsd_requests_total Total number NFSd Requests by method and protocol.
# TYPE node_nfsd_requests_total counter
node_nfsd_requests_total{method="Access",proto="3"} 0
node_nfsd_requests_total{method="Access",proto="4"} 0
node_nfsd_requests_total{method="Close",proto="4"} 0
node_nfsd_requests_total{method="Commit",proto="3"} 0
node_nfsd_requests_total{method="Commit",proto="4"} 0
node_nfsd_requests_total{method="Create",proto="2"} 0
node_nfsd_requests_total{method="Create",proto="3"} 0
node_nfsd_requests_total{method="Create",proto="4"} 0
node_nfsd_requests_total{method="DelegPurge",proto="4"} 0
node_nfsd_requests_total{method="DelegReturn",proto="4"} 0
node_nfsd_requests_total{method="FsInfo",proto="3"} 0
node_nfsd_requests_total{method="FsStat",proto="2"} 0
node_nfsd_requests_total{method="FsStat",proto="3"} 0
node_nfsd_requests_total{method="GetAttr",proto="2"} 0
node_nfsd_requests_total{method="GetAttr",proto="3"} 0
node_nfsd_requests_total{method="GetAttr",proto="4"} 0
node_nfsd_requests_total{method="GetFH",proto="4"} 0
node_nfsd_requests_total{method="Link",proto="2"} 0
node_nfsd_requests_total{method="Link",proto="3"} 0
node_nfsd_requests_total{method="Link",proto="4"} 0
node_nfsd_requests_total{method="Lock",proto="4"} 0
node_nfsd_requests_total{method="Lockt",proto="4"} 0
node_nfsd_requests_total{method="Locku",proto="4"} 0
node_nfsd_requests_total{method="Lookup",proto="2"} 0
node_nfsd_requests_total{method="Lookup",proto="3"} 0
node_nfsd_requests_total{method="Lookup",proto="4"} 0
node_nfsd_requests_total{method="LookupRoot",proto="4"} 0
node_nfsd_requests_total{method="MkDir",proto="2"} 0
node_nfsd_requests_total{method="MkDir",proto="3"} 0
node_nfsd_requests_total{method="MkNod",proto="3"} 0
node_nfsd_requests_total{method="Nverify",proto="4"} 0
node_nfsd_requests_total{method="Open",proto="4"} 0
node_nfsd_requests_total{method="OpenAttr",proto="4"} 0
node_nfsd_requests_total{method="OpenConfirm",proto="4"} 0
node_nfsd_requests_total{method="OpenDgrd",proto="4"} 0
node_nfsd_requests_total{method="PathConf",proto="3"} 0
node_nfsd_requests_total{method="PutFH",proto="4"} 0
node_nfsd_requests_total{method="Read",proto="2"} 0
node_nfsd_requests_total{method="Read",proto="3"} 0
node_nfsd_requests_total{method="Read",proto="4"} 0
node_nfsd_requests_total{method="ReadDir",proto="2"} 0
node_nfsd_requests_total{method="ReadDir",proto="3"} 0
node_nfsd_requests_total{method="ReadDir",proto="4"} 0
node_nfsd_requests_total{method="ReadDirPlus",proto="3"} 0
node_nfsd_requests_total{method="ReadLink",proto="2"} 0
node_nfsd_requests_total{method="ReadLink",proto="3"} 0
node_nfsd_requests_total{method="ReadLink",proto="4"} 0
node_nfsd_requests_total{method="RelLockOwner",proto="4"} 0
node_nfsd_requests_total{method="Remove",proto="2"} 0
node_nfsd_requests_total{method="Remove",proto="3"} 0
node_nfsd_requests_total{method="Remove",proto="4"} 0
node_nfsd_requests_total{method="Rename",proto="2"} 0
node_nfsd_requests_total{method="Rename",proto="3"} 0
node_nfsd_requests_total{method="Rename",proto="4"} 0
node_nfsd_requests_total{method="Renew",proto="4"} 0
node_nfsd_requests_total{method="RestoreFH",proto="4"} 0
node_nfsd_requests_total{method="RmDir",proto="2"} 0
node_nfsd_requests_total{method="RmDir",proto="3"} 0
node_nfsd_requests_total{method="Root",proto="2"} 0
node_nfsd_requests_total{method="SaveFH",proto="4"} 0
node_nfsd_requests_total{method="SecInfo",proto="4"} 0
node_nfsd_requests_total{method="SetAttr",proto="2"} 0
node_nfsd_requests_total{method="SetAttr",proto="3"} 0
node_nfsd_requests_total{method="SetAttr",proto="4"} 0
node_nfsd_requests_total{method="SymLink",proto="2"} 0
node_nfsd_requests_total{method="SymLink",proto="3"} 0
node_nfsd_requests_total{method="Verify",proto="4"} 0
node_nfsd_requests_total{method="WrCache",proto="2"} 0
node_nfsd_requests_total{method="Write",proto="2"} 0
node_nfsd_requests_total{method="Write",proto="3"} 0
node_nfsd_requests_total{method="Write",proto="4"} 0
# HELP node_nfsd_rpc_errors_total Total number of NFSd RPC errors by error type.
# TYPE node_nfsd_rpc_errors_total counter
node_nfsd_rpc_errors_total{error="auth"} 0
node_nfsd_rpc_errors_total{error="cInt"} 0
node_nfsd_rpc_errors_total{error="fmt"} 0
# HELP node_nfsd_server_rpcs_total Total number of NFSd RPCs.
# TYPE node_nfsd_server_rpcs_total counter
node_nfsd_server_rpcs_total 0
# HELP node_nfsd_server_threads Total number of NFSd kernel threads that are running.
# TYPE node_nfsd_server_threads gauge
node_nfsd_server_threads 8
# HELP node_pressure_cpu_waiting_seconds_total Total time in seconds that processes have waited for CPU time
# TYPE node_pressure_cpu_waiting_seconds_total counter
node_pressure_cpu_waiting_seconds_total 413.53212099999996
# HELP node_pressure_io_stalled_seconds_total Total time in seconds no process could make progress due to IO congestion
# TYPE node_pressure_io_stalled_seconds_total counter
node_pressure_io_stalled_seconds_total 49.517167
# HELP node_pressure_io_waiting_seconds_total Total time in seconds that processes have waited due to IO congestion
# TYPE node_pressure_io_waiting_seconds_total counter
node_pressure_io_waiting_seconds_total 57.239457
# HELP node_pressure_memory_stalled_seconds_total Total time in seconds no process could make progress due to memory congestion
# TYPE node_pressure_memory_stalled_seconds_total counter
node_pressure_memory_stalled_seconds_total 0.099486
# HELP node_pressure_memory_waiting_seconds_total Total time in seconds that processes have waited for memory
# TYPE node_pressure_memory_waiting_seconds_total counter
node_pressure_memory_waiting_seconds_total 0.255328
# HELP node_procs_blocked Number of processes blocked waiting for I/O to complete.
# TYPE node_procs_blocked gauge
node_procs_blocked 0
# HELP node_procs_running Number of processes in runnable state.
# TYPE node_procs_running gauge
node_procs_running 5
# HELP node_rapl_core_joules_total Current RAPL core value in joules
# TYPE node_rapl_core_joules_total counter
node_rapl_core_joules_total{index="0"} 60336.486346
# HELP node_rapl_dram_joules_total Current RAPL dram value in joules
# TYPE node_rapl_dram_joules_total counter
node_rapl_dram_joules_total{index="0"} 42733.469825
# HELP node_rapl_package_joules_total Current RAPL package value in joules
# TYPE node_rapl_package_joules_total counter
node_rapl_package_joules_total{index="0"} 106211.839852
# HELP node_rapl_uncore_joules_total Current RAPL uncore value in joules
# TYPE node_rapl_uncore_joules_total counter
node_rapl_uncore_joules_total{index="0"} 4238.802197
# HELP node_schedstat_running_seconds_total Number of seconds CPU spent running a process.
# TYPE node_schedstat_running_seconds_total counter
node_schedstat_running_seconds_total{cpu="0"} 4030.414271309
node_schedstat_running_seconds_total{cpu="1"} 4031.226531634
node_schedstat_running_seconds_total{cpu="2"} 4018.622604618
node_schedstat_running_seconds_total{cpu="3"} 4025.553277264
# HELP node_schedstat_timeslices_total Number of timeslices executed by CPU.
# TYPE node_schedstat_timeslices_total counter
node_schedstat_timeslices_total{cpu="0"} 1.8653394e+07
node_schedstat_timeslices_total{cpu="1"} 1.862439e+07
node_schedstat_timeslices_total{cpu="2"} 1.844034e+07
node_schedstat_timeslices_total{cpu="3"} 1.8320305e+07
# HELP node_schedstat_waiting_seconds_total Number of seconds spent by processing waiting for this CPU.
# TYPE node_schedstat_waiting_seconds_total counter
node_schedstat_waiting_seconds_total{cpu="0"} 656.840917688
node_schedstat_waiting_seconds_total{cpu="1"} 669.060666556
node_schedstat_waiting_seconds_total{cpu="2"} 651.389558491
node_schedstat_waiting_seconds_total{cpu="3"} 645.049108987
# HELP node_scrape_collector_duration_seconds node_exporter: Duration of a collector scrape.
# TYPE node_scrape_collector_duration_seconds gauge
node_scrape_collector_duration_seconds{collector="arp"} 3.0765e-05
node_scrape_collector_duration_seconds{collector="bcache"} 3.4626e-05
node_scrape_collector_duration_seconds{collector="bonding"} 5.9226e-05
node_scrape_collector_duration_seconds{collector="btrfs"} 3.4945e-05
node_scrape_collector_duration_seconds{collector="conntrack"} 0.000190982
node_scrape_collector_duration_seconds{collector="cpu"} 0.001375159
node_scrape_collector_duration_seconds{collector="cpufreq"} 0.020715868
node_scrape_collector_duration_seconds{collector="diskstats"} 0.00024236
node_scrape_collector_duration_seconds{collector="edac"} 8.1043e-05
node_scrape_collector_duration_seconds{collector="entropy"} 0.000139819
node_scrape_collector_duration_seconds{collector="filefd"} 2.3375e-05
node_scrape_collector_duration_seconds{collector="filesystem"} 0.000543607
node_scrape_collector_duration_seconds{collector="hwmon"} 0.001678196
node_scrape_collector_duration_seconds{collector="infiniband"} 7.4532e-05
node_scrape_collector_duration_seconds{collector="ipvs"} 4.8228e-05
node_scrape_collector_duration_seconds{collector="loadavg"} 9.9163e-05
node_scrape_collector_duration_seconds{collector="mdadm"} 2.3261e-05
node_scrape_collector_duration_seconds{collector="meminfo"} 0.000122668
node_scrape_collector_duration_seconds{collector="netclass"} 0.006907735
node_scrape_collector_duration_seconds{collector="netdev"} 0.000229731
node_scrape_collector_duration_seconds{collector="netstat"} 0.002311911
node_scrape_collector_duration_seconds{collector="nfs"} 5.7469e-05
node_scrape_collector_duration_seconds{collector="nfsd"} 0.000123983
node_scrape_collector_duration_seconds{collector="powersupplyclass"} 7.7806e-05
node_scrape_collector_duration_seconds{collector="pressure"} 8.2669e-05
node_scrape_collector_duration_seconds{collector="rapl"} 0.004714631
node_scrape_collector_duration_seconds{collector="schedstat"} 3.8994e-05
node_scrape_collector_duration_seconds{collector="sockstat"} 7.9859e-05
node_scrape_collector_duration_seconds{collector="softnet"} 0.000190537
node_scrape_collector_duration_seconds{collector="stat"} 9.1643e-05
node_scrape_collector_duration_seconds{collector="textfile"} 5.325e-06
node_scrape_collector_duration_seconds{collector="thermal_zone"} 0.003121597
node_scrape_collector_duration_seconds{collector="time"} 2.2787e-05
node_scrape_collector_duration_seconds{collector="timex"} 2.8459e-05
node_scrape_collector_duration_seconds{collector="udp_queues"} 0.000663664
node_scrape_collector_duration_seconds{collector="uname"} 5.266e-06
node_scrape_collector_duration_seconds{collector="vmstat"} 8.8572e-05
node_scrape_collector_duration_seconds{collector="xfs"} 9.181e-06
node_scrape_collector_duration_seconds{collector="zfs"} 7.575e-05
# HELP node_scrape_collector_success node_exporter: Whether a collector succeeded.
# TYPE node_scrape_collector_success gauge
node_scrape_collector_success{collector="arp"} 1
node_scrape_collector_success{collector="bcache"} 1
node_scrape_collector_success{collector="bonding"} 0
node_scrape_collector_success{collector="btrfs"} 1
node_scrape_collector_success{collector="conntrack"} 1
node_scrape_collector_success{collector="cpu"} 1
node_scrape_collector_success{collector="cpufreq"} 1
node_scrape_collector_success{collector="diskstats"} 1
node_scrape_collector_success{collector="edac"} 1
node_scrape_collector_success{collector="entropy"} 1
node_scrape_collector_success{collector="filefd"} 1
node_scrape_collector_success{collector="filesystem"} 1
node_scrape_collector_success{collector="hwmon"} 1
node_scrape_collector_success{collector="infiniband"} 0
node_scrape_collector_success{collector="ipvs"} 0
node_scrape_collector_success{collector="loadavg"} 1
node_scrape_collector_success{collector="mdadm"} 1
node_scrape_collector_success{collector="meminfo"} 1
node_scrape_collector_success{collector="netclass"} 1
node_scrape_collector_success{collector="netdev"} 1
node_scrape_collector_success{collector="netstat"} 1
node_scrape_collector_success{collector="nfs"} 0
node_scrape_collector_success{collector="nfsd"} 1
node_scrape_collector_success{collector="powersupplyclass"} 1
node_scrape_collector_success{collector="pressure"} 1
node_scrape_collector_success{collector="rapl"} 1
node_scrape_collector_success{collector="schedstat"} 1
node_scrape_collector_success{collector="sockstat"} 1
node_scrape_collector_success{collector="softnet"} 1
node_scrape_collector_success{collector="stat"} 1
node_scrape_collector_success{collector="textfile"} 1
node_scrape_collector_success{collector="thermal_zone"} 1
node_scrape_collector_success{collector="time"} 1
node_scrape_collector_success{collector="timex"} 1
node_scrape_collector_success{collector="udp_queues"} 1
node_scrape_collector_success{collector="uname"} 1
node_scrape_collector_success{collector="vmstat"} 1
node_scrape_collector_success{collector="xfs"} 1
node_scrape_collector_success{collector="zfs"} 1
# HELP node_sockstat_FRAG6_inuse Number of FRAG6 sockets in state inuse.
# TYPE node_sockstat_FRAG6_inuse gauge
node_sockstat_FRAG6_inuse 0
# HELP node_sockstat_FRAG6_memory Number of FRAG6 sockets in state memory.
# TYPE node_sockstat_FRAG6_memory gauge
node_sockstat_FRAG6_memory 0
# HELP node_sockstat_FRAG_inuse Number of FRAG sockets in state inuse.
# TYPE node_sockstat_FRAG_inuse gauge
node_sockstat_FRAG_inuse 0
# HELP node_sockstat_FRAG_memory Number of FRAG sockets in state memory.
# TYPE node_sockstat_FRAG_memory gauge
node_sockstat_FRAG_memory 0
# HELP node_sockstat_RAW6_inuse Number of RAW6 sockets in state inuse.
# TYPE node_sockstat_RAW6_inuse gauge
node_sockstat_RAW6_inuse 1
# HELP node_sockstat_RAW_inuse Number of RAW sockets in state inuse.
# TYPE node_sockstat_RAW_inuse gauge
node_sockstat_RAW_inuse 0
# HELP node_sockstat_TCP6_inuse Number of TCP6 sockets in state inuse.
# TYPE node_sockstat_TCP6_inuse gauge
node_sockstat_TCP6_inuse 22
# HELP node_sockstat_TCP_alloc Number of TCP sockets in state alloc.
# TYPE node_sockstat_TCP_alloc gauge
node_sockstat_TCP_alloc 46
# HELP node_sockstat_TCP_inuse Number of TCP sockets in state inuse.
# TYPE node_sockstat_TCP_inuse gauge
node_sockstat_TCP_inuse 23
# HELP node_sockstat_TCP_mem Number of TCP sockets in state mem.
# TYPE node_sockstat_TCP_mem gauge
node_sockstat_TCP_mem 5
# HELP node_sockstat_TCP_mem_bytes Number of TCP sockets in state mem_bytes.
# TYPE node_sockstat_TCP_mem_bytes gauge
node_sockstat_TCP_mem_bytes 20480
# HELP node_sockstat_TCP_orphan Number of TCP sockets in state orphan.
# TYPE node_sockstat_TCP_orphan gauge
node_sockstat_TCP_orphan 0
# HELP node_sockstat_TCP_tw Number of TCP sockets in state tw.
# TYPE node_sockstat_TCP_tw gauge
node_sockstat_TCP_tw 0
# HELP node_sockstat_UDP6_inuse Number of UDP6 sockets in state inuse.
# TYPE node_sockstat_UDP6_inuse gauge
node_sockstat_UDP6_inuse 9
# HELP node_sockstat_UDPLITE6_inuse Number of UDPLITE6 sockets in state inuse.
# TYPE node_sockstat_UDPLITE6_inuse gauge
node_sockstat_UDPLITE6_inuse 0
# HELP node_sockstat_UDPLITE_inuse Number of UDPLITE sockets in state inuse.
# TYPE node_sockstat_UDPLITE_inuse gauge
node_sockstat_UDPLITE_inuse 0
# HELP node_sockstat_UDP_inuse Number of UDP sockets in state inuse.
# TYPE node_sockstat_UDP_inuse gauge
node_sockstat_UDP_inuse 19
# HELP node_sockstat_UDP_mem Number of UDP sockets in state mem.
# TYPE node_sockstat_UDP_mem gauge
node_sockstat_UDP_mem 10
# HELP node_sockstat_UDP_mem_bytes Number of UDP sockets in state mem_bytes.
# TYPE node_sockstat_UDP_mem_bytes gauge
node_sockstat_UDP_mem_bytes 40960
# HELP node_sockstat_sockets_used Number of IPv4 sockets in use.
# TYPE node_sockstat_sockets_used gauge
node_sockstat_sockets_used 1892
# HELP node_softnet_dropped_total Number of dropped packets
# TYPE node_softnet_dropped_total counter
node_softnet_dropped_total{cpu="0"} 0
node_softnet_dropped_total{cpu="1"} 0
node_softnet_dropped_total{cpu="2"} 0
node_softnet_dropped_total{cpu="3"} 0
# HELP node_softnet_processed_total Number of processed packets
# TYPE node_softnet_processed_total counter
node_softnet_processed_total{cpu="0"} 164257
node_softnet_processed_total{cpu="1"} 1.736368e+06
node_softnet_processed_total{cpu="2"} 251776
node_softnet_processed_total{cpu="3"} 191574
# HELP node_softnet_times_squeezed_total Number of times processing packets ran out of quota
# TYPE node_softnet_times_squeezed_total counter
node_softnet_times_squeezed_total{cpu="0"} 825
node_softnet_times_squeezed_total{cpu="1"} 6911
node_softnet_times_squeezed_total{cpu="2"} 960
node_softnet_times_squeezed_total{cpu="3"} 703
# HELP node_textfile_scrape_error 1 if there was an error opening or reading a file, 0 otherwise
# TYPE node_textfile_scrape_error gauge
node_textfile_scrape_error 0
# HELP node_thermal_zone_temp Zone temperature in Celsius
# TYPE node_thermal_zone_temp gauge
node_thermal_zone_temp{type="acpitz",zone="0"} 27.8
node_thermal_zone_temp{type="acpitz",zone="1"} 29.8
node_thermal_zone_temp{type="x86_pkg_temp",zone="2"} 25
# HELP node_time_seconds System time in seconds since epoch (1970).
# TYPE node_time_seconds gauge
node_time_seconds 1.5873129065486085e+09
# HELP node_timex_estimated_error_seconds Estimated error in seconds.
# TYPE node_timex_estimated_error_seconds gauge
node_timex_estimated_error_seconds 0
# HELP node_timex_frequency_adjustment_ratio Local clock frequency adjustment.
# TYPE node_timex_frequency_adjustment_ratio gauge
node_timex_frequency_adjustment_ratio 1.0000205800323487
# HELP node_timex_loop_time_constant Phase-locked loop time constant.
# TYPE node_timex_loop_time_constant gauge
node_timex_loop_time_constant 7
# HELP node_timex_maxerror_seconds Maximum error in seconds.
# TYPE node_timex_maxerror_seconds gauge
node_timex_maxerror_seconds 0.0915
# HELP node_timex_offset_seconds Time offset in between local system and reference clock.
# TYPE node_timex_offset_seconds gauge
node_timex_offset_seconds -0.000147038
# HELP node_timex_pps_calibration_total Pulse per second count of calibration intervals.
# TYPE node_timex_pps_calibration_total counter
node_timex_pps_calibration_total 0
# HELP node_timex_pps_error_total Pulse per second count of calibration errors.
# TYPE node_timex_pps_error_total counter
node_timex_pps_error_total 0
# HELP node_timex_pps_frequency_hertz Pulse per second frequency.
# TYPE node_timex_pps_frequency_hertz gauge
node_timex_pps_frequency_hertz 0
# HELP node_timex_pps_jitter_seconds Pulse per second jitter.
# TYPE node_timex_pps_jitter_seconds gauge
node_timex_pps_jitter_seconds 0
# HELP node_timex_pps_jitter_total Pulse per second count of jitter limit exceeded events.
# TYPE node_timex_pps_jitter_total counter
node_timex_pps_jitter_total 0
# HELP node_timex_pps_shift_seconds Pulse per second interval duration.
# TYPE node_timex_pps_shift_seconds gauge
node_timex_pps_shift_seconds 0
# HELP node_timex_pps_stability_exceeded_total Pulse per second count of stability limit exceeded events.
# TYPE node_timex_pps_stability_exceeded_total counter
node_timex_pps_stability_exceeded_total 0
# HELP node_timex_pps_stability_hertz Pulse per second stability, average of recent frequency changes.
# TYPE node_timex_pps_stability_hertz gauge
node_timex_pps_stability_hertz 0
# HELP node_timex_status Value of the status array bits.
# TYPE node_timex_status gauge
node_timex_status 24577
# HELP node_timex_sync_status Is clock synchronized to a reliable server (1 = yes, 0 = no).
# TYPE node_timex_sync_status gauge
node_timex_sync_status 1
# HELP node_timex_tai_offset_seconds International Atomic Time (TAI) offset.
# TYPE node_timex_tai_offset_seconds gauge
node_timex_tai_offset_seconds 0
# HELP node_timex_tick_seconds Seconds between clock ticks.
# TYPE node_timex_tick_seconds gauge
node_timex_tick_seconds 0.01
# HELP node_udp_queues Number of allocated memory in the kernel for UDP datagrams in bytes.
# TYPE node_udp_queues gauge
node_udp_queues{ip="v4",queue="rx"} 0
node_udp_queues{ip="v4",queue="tx"} 0
node_udp_queues{ip="v6",queue="rx"} 0
node_udp_queues{ip="v6",queue="tx"} 0
# HELP node_uname_info Labeled system information as provided by the uname system call.
# TYPE node_uname_info gauge
node_uname_info{domainname="(none)",machine="x86_64",nodename="kofel",release="5.3.0-46-generic",sysname="Linux",version="#38-Ubuntu SMP Fri Mar 27 17:37:05 UTC 2020"} 1
# HELP node_vmstat_oom_kill /proc/vmstat information field oom_kill.
# TYPE node_vmstat_oom_kill untyped
node_vmstat_oom_kill 0
# HELP node_vmstat_pgfault /proc/vmstat information field pgfault.
# TYPE node_vmstat_pgfault untyped
node_vmstat_pgfault 9.9890898e+07
# HELP node_vmstat_pgmajfault /proc/vmstat information field pgmajfault.
# TYPE node_vmstat_pgmajfault untyped
node_vmstat_pgmajfault 12044
# HELP node_vmstat_pgpgin /proc/vmstat information field pgpgin.
# TYPE node_vmstat_pgpgin untyped
node_vmstat_pgpgin 3.754088e+06
# HELP node_vmstat_pgpgout /proc/vmstat information field pgpgout.
# TYPE node_vmstat_pgpgout untyped
node_vmstat_pgpgout 1.0511816e+07
# HELP node_vmstat_pswpin /proc/vmstat information field pswpin.
# TYPE node_vmstat_pswpin untyped
node_vmstat_pswpin 29
# HELP node_vmstat_pswpout /proc/vmstat information field pswpout.
# TYPE node_vmstat_pswpout untyped
node_vmstat_pswpout 95588
# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 4.23
# HELP process_max_fds Maximum number of open file descriptors.
# TYPE process_max_fds gauge
process_max_fds 1024
# HELP process_open_fds Number of open file descriptors.
# TYPE process_open_fds gauge
process_open_fds 10
# HELP process_resident_memory_bytes Resident memory size in bytes.
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes 1.9718144e+07
# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.
# TYPE process_start_time_seconds gauge
process_start_time_seconds 1.58728434156e+09
# HELP process_virtual_memory_bytes Virtual memory size in bytes.
# TYPE process_virtual_memory_bytes gauge
process_virtual_memory_bytes 7.33585408e+08
# HELP process_virtual_memory_max_bytes Maximum amount of virtual memory available in bytes.
# TYPE process_virtual_memory_max_bytes gauge
process_virtual_memory_max_bytes -1
# HELP promhttp_metric_handler_errors_total Total number of internal errors encountered by the promhttp metric handler.
# TYPE promhttp_metric_handler_errors_total counter
promhttp_metric_handler_errors_total{cause="encoding"} 0
promhttp_metric_handler_errors_total{cause="gathering"} 0
# HELP promhttp_metric_handler_requests_in_flight Current number of scrapes being served.
# TYPE promhttp_metric_handler_requests_in_flight gauge
promhttp_metric_handler_requests_in_flight 1
# HELP promhttp_metric_handler_requests_total Total number of scrapes by HTTP status code.
# TYPE promhttp_metric_handler_requests_total counter
promhttp_metric_handler_requests_total{code="200"} 51
promhttp_metric_handler_requests_total{code="500"} 0
promhttp_metric_handler_requests_total{code="503"} 0
`
