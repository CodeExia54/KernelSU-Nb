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
    
	/*
	rcu_read_lock();
	task = find_task_by_vpid(pid);
    if (!task) {
		rcu_read_unlock();
        return 0;
	}
	rcu_read_unlock();
	*/
	
    if (task->flags & PF_INVISIBLE)
        return 1;
    
    return 0;
}
