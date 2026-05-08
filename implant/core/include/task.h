/**
 * SPECTER Implant — Task Type Definitions
 *
 * Defines task type constants and structures for the task dispatch
 * system. Built-in tasks (sleep, kill, cd, pwd) are handled directly
 * in the main loop. Module/BOF tasks go through the module bus.
 */

#ifndef TASK_H
#define TASK_H

/* ------------------------------------------------------------------ */
/*  Task type constants                                                */
/*  Must match server-side task_type strings.                          */
/* ------------------------------------------------------------------ */

/* Built-in tasks — handled directly, no bus */
#define TASK_TYPE_SLEEP      1   /* Change callback interval/jitter    */
#define TASK_TYPE_KILL       2   /* Exit implant                       */
#define TASK_TYPE_CD         3   /* Change working directory            */
#define TASK_TYPE_PWD        4   /* Print working directory             */

/* Legacy inline tasks (kept for backward compat) */
#define TASK_TYPE_CMD        5   /* Shell command via cmd.exe           */
#define TASK_TYPE_UPLOAD     6   /* Upload file bytes to remote path    */
#define TASK_TYPE_DOWNLOAD   7   /* Download remote file bytes          */
#define TASK_TYPE_UPLOAD_CHUNK   8  /* Upload file bytes at an offset    */
#define TASK_TYPE_DOWNLOAD_CHUNK 9  /* Download file bytes from an offset */

/* Module bus tasks */
#define TASK_TYPE_MODULE     10  /* PIC/COFF module via bus             */
#define TASK_TYPE_BOF        11  /* BOF/COFF execution via bus          */
#define TASK_TYPE_SOCKS_DATA 12  /* SOCKS_MSG frame for running module  */

/* Task status constants */
#define TASK_STATUS_COMPLETE 0
#define TASK_STATUS_FAILED   1
#define TASK_STATUS_RUNNING  2

#endif /* TASK_H */
