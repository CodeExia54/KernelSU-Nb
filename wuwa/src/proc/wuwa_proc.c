#include "wuwa_proc.h"

int is_invisible(pid_t pid) {
    struct task_struct* task;
    struct pid * pid_struct;

    if (!pid)
        return 0;
	
    pid_struct = find_get_pid(pid);
	if (!pid_struct)
	    return 0;
    
	task = pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
		return 0;		
      
    if (task->flags & PF_INVISIBLE)
        return 1;
    
    return 0;
}
