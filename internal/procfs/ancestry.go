package procfs

// Ancestry walks /proc/pid/status PPid chain up to `maxDepth` ancestors and
// returns their comms in order from immediate parent to furthest ancestor.
// Unreachable PIDs terminate the walk; a loop (PPid==pid) also terminates.
// Returns at most maxDepth entries; callers typically use 6–8.
func Ancestry(pid, maxDepth int) []string {
	out := make([]string, 0, maxDepth)
	cur := pid
	for i := 0; i < maxDepth; i++ {
		ppid, err := PPid(cur)
		if err != nil || ppid == 0 || ppid == cur {
			return out
		}
		comm, err := Comm(ppid)
		if err != nil {
			return out
		}
		out = append(out, comm)
		cur = ppid
	}
	return out
}
