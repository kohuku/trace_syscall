#ifndef __EVENT_H__
#define __EVENT_H__

/*!
 *  \brief  information tracked by pamspy
 */
typedef struct _event_t {
    int pid;
    int uid;
    int euid;
    int suid;
    int new_uid;
    int new_euid;
    int new_suid;
    int error_flag;
    int syscall_no;
    char comm[16];
} event_t;

#endif
