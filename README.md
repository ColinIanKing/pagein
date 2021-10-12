# Pagein

Pagein is a tool that forces pages that are in swap to be paged in back to memory. The main usecase for pagein is to exercise the VM and swap subsystems for testing purposes.

pagein command line options:

* -a try to page in all processes.
* -h help
* -p page in process with process ID pid
* -v verbose mode 

## Example:

```
sudo pagein -a
Processes scanned:     271
Kernel threads:        130 (skipped)
Processes touched:     140
Pages touched:         1834340
Free memory decrease:  2233252K (558313 pages)
Swap memory decrease:  -27012K (-6753 pages)
Page faults major:     2850
Page faults minor:     468453
Swaps:                 0
```
