#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "filesys/file.h"
#include <stdio.h>
#include "kernel/stdio.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"

typedef int pid_t;

static void syscall_handler (struct intr_frame *);

static struct lock files_sync_lock;              /* lock for sychronization between files */
static struct lock executing;                    /* lock for sychronization between files */
void *get_void_ptr (void *esp);                  /* get void pointer */
void validate_void_ptr (void *ptr);              /* chack if the pointer is valid */
struct file *get_target_file (int fd);           /* return file corresponding to given fd */
struct list_elem *get_target_fileelem (int fd);  /* return file element corresponding to given fd */

/* Actual System calls */

void exit (int status);
pid_t exec (const char* cmd_line);
int wait (tid_t child_tid UNUSED);
bool create (const char* file, unsigned initial_size);
bool remove (const char* file);
int open (const char* file);
int filesize (int fd);
int read (int fd, const void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
 
void 
syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&files_sync_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  validate_void_ptr(f->esp);
  int sys_code = *(int *)f->esp;
  
  switch (sys_code)
    {
    case SYS_HALT:
    {
      shutdown_power_off();
      break;
    }
    case SYS_EXIT:
    {
      exit_wrapper(f);
      break;
    }
    case SYS_EXEC:
    {
      exec_wrapper (f);
      break;
    }
    case SYS_WAIT:
    {
      wait_wrapper(f);
      break;
    }
    case SYS_CREATE:
    {
      create_wrapper (f);
      break;
    }
    case SYS_REMOVE:
    {
      remove_wrapper (f);
      break;
    }
    case SYS_OPEN:
    {
      open_wrapper(f);
      break;
    }
    case SYS_FILESIZE:
    {
      filesize_wrapper(f);
      break;
    }
    case SYS_READ:
    {
      read_wrapper (f);
      break;
    }
    case SYS_WRITE:
    {
      write_wrapper(f);
      break;
    }
    case SYS_SEEK:
    {
      seek_wrapper (f);
      break;
    }
    case SYS_TELL:
    {
      tell_wrapper (f);
      break;
    }
    case SYS_CLOSE:
    {
      close_wrapper(f);
      break;
    }
    default:
    {
      exit(-1);
    }
  }
}

void 
exit_wrapper (struct intr_frame *f UNUSED)
{
  int *status = f->esp + sizeof(int*);
  validate_void_ptr (status);

  exit(*status);
}

void 
exec_wrapper (struct intr_frame *f)
{
  char** cmd_line = f->esp + sizeof(int*);
  validate_void_ptr (*cmd_line);

  f->eax = exec(*cmd_line);
}

void 
wait_wrapper (struct intr_frame *f UNUSED)
{
  int* tid = f->esp + sizeof(int*);
  validate_void_ptr (tid);

  f->eax=wait (*tid);  
}

void 
create_wrapper (struct intr_frame *f UNUSED)
{
  char** file = f->esp + sizeof(int*);
  validate_void_ptr (*file);
  unsigned* size = (f->esp) + sizeof(int*) + sizeof(char*);
  validate_void_ptr (size);

  if (*file == NULL)
    exit (-1);
  
  f->eax = create (*file, *size);
}

void 
remove_wrapper (struct intr_frame *f UNUSED)
{
  char** file = f->esp + sizeof(int*);
  validate_void_ptr (*file);
  if (*file == NULL)
    exit (-1);
 
  f->eax = remove (*file);
}

void 
open_wrapper (struct intr_frame *f UNUSED)
{
  char** file = f->esp + sizeof(int*);
  validate_void_ptr (*file);

  f->eax = open (*file);
}

void 
filesize_wrapper (struct intr_frame *f UNUSED)
{
  int* fd = f->esp + sizeof(int *);
  validate_void_ptr (fd);

  f->eax = filesize(*fd);
}

void 
read_wrapper (struct intr_frame *f UNUSED)
{  
  int *fd = f->esp + sizeof(int*);
  validate_void_ptr (fd);
  void **buffer = f->esp + 2*sizeof(int*);
  validate_void_ptr (*buffer);
  unsigned *size = (f->esp) + 2*sizeof(int*) + sizeof(void**);
  validate_void_ptr (size);
 
  f->eax = read(*fd, *buffer, *size);
}

void 
write_wrapper (struct intr_frame *f UNUSED)
{
  int *fd = f->esp + sizeof(int*);
  validate_void_ptr (fd);
  void **buffer = f->esp + 2*sizeof(int*);
  validate_void_ptr (*buffer);
  unsigned *size = (f->esp) + 2*sizeof(int*) + sizeof(void**);
  validate_void_ptr (size);
  
  f->eax = write(*fd, *buffer, *size);
}

void 
seek_wrapper (struct intr_frame *f UNUSED)
{
  int* fd = f->esp + sizeof(int*);
  validate_void_ptr (fd);
  unsigned* position = (f->esp) + sizeof(int*) + sizeof(int);
  validate_void_ptr (position);

  seek (*fd, *position);
}

void 
tell_wrapper (struct intr_frame *f UNUSED)
{
  int* fd = f->esp + sizeof(int*);
  validate_void_ptr (fd);

  f->eax = tell (*fd);
}

void 
close_wrapper (struct intr_frame *f UNUSED) 
{
  int* fd = f->esp + sizeof(int*);
  validate_void_ptr (fd);

  close (*fd);  
}

/* Actual System Calls */

void 
exit (int status)
{
  if(lock_held_by_current_thread(&files_sync_lock))
      lock_release (&files_sync_lock);

  struct thread *current_thread = thread_current ();
  printf("%s: exit(%d)\n", current_thread->name, status); /* REQUIRED */

  /* closing all opened files */
  struct list_elem *e = list_begin (&current_thread->open_files);

  while (e != list_tail (&current_thread->open_files))
  {
    struct list_elem *next = list_next (e);
    struct open_file *file = list_entry(e, struct open_file, fileelem);
    list_remove (&file->fileelem);
	  file_close (file->ptr);
    free (file);
    e = next;
  }

  if(thread_current()->executable != NULL)
  {
    file_allow_write (thread_current()->executable);
    file_close (thread_current()->executable);
  }

  if(thread_current()->parent_thread != NULL && thread_current()->parent_thread->waiting_on == thread_current()->tid)
  {
    thread_current ()->parent_thread->waiting_on = -1;
    thread_current ()->parent_thread->child_exit_status = status;
    sema_up(&thread_current()->parent_thread->parent_child_sync);
  }
  else  
  {
    list_remove (&thread_current()->childelem);
  }

  /* waking up all current threads children */
  struct thread *child = NULL;
  struct list_elem *elem ;
  
  while (!list_empty(&thread_current()->children))
  {
    elem = list_pop_back (elem);
    child = list_entry(elem, struct thread, childelem);
    list_remove (&child->childelem);
    sema_up(&child->parent_child_sync);
    free(child);
  }
  thread_exit ();
}

pid_t 
exec (const char* cmd_line)
{
  return process_execute(cmd_line);
}

int 
wait (tid_t child_tid)
{
  return process_wait(child_tid);
}

bool 
create (const char* file, unsigned initial_size)
{
  return filesys_create (file ,initial_size);
}

bool 
remove (const char* file)
{
  lock_acquire (&files_sync_lock);
  bool returned = filesys_remove(file);
  lock_release (&files_sync_lock);
  return returned;
}

int 
open (const char* file) 
{
  if (file == NULL) return -1;
  int ret = 0;
  lock_acquire(&files_sync_lock);
  struct file *of = filesys_open(file);
  if (of == NULL) return -1;

  thread_current()->fd_last++;
  struct open_file *open = malloc(sizeof *open);
  open->ptr = of;
  open->fd = thread_current()->fd_last++;

  list_push_back(&thread_current()->open_files, &open->fileelem);
  lock_release(&files_sync_lock);

  return open->fd;
}

int 
filesize (int fd)
{
  struct file *target_file = get_target_file(fd);
  if(target_file == NULL) return -1;
  lock_acquire (&files_sync_lock);
  int ret = file_length(target_file);
  lock_release (&files_sync_lock);
  return ret;
}

int 
read (int fd, const void *buffer, unsigned size)
{
  if (fd == 1)
  {
    /* negative area */
    return 0;
  }
  else if (fd == 0)
  {
    char *line = (char *)buffer;
    unsigned i = 0;
    for (; i < size; i++)
    {
      lock_acquire (&files_sync_lock);
      line[i] = input_getc();
      lock_release (&files_sync_lock);
    }
    return i;
  }
  else
  {
    struct file *target_file = get_target_file(fd);
    if (target_file == NULL) return -1;
    lock_acquire(&files_sync_lock);
    int returned = file_read(target_file, buffer, size);
    lock_release(&files_sync_lock);
    return returned;
  }
}

int 
write (int fd, const void *buffer, unsigned size)
{
  if (fd == 0)
  {
    /* negative area */
    return 0;
  }
  else if (fd == 1)
  {
    unsigned temp_size = size;
    while (temp_size > 100)
    {
      putbuf(buffer, 100);
      temp_size = temp_size - 100;
      buffer = buffer + 100;
    }
    putbuf(buffer, temp_size);
    return size;
  }
  else
  {
    struct file *target_file = get_target_file(fd);
    if (target_file == NULL) return -1;    
    lock_acquire(&files_sync_lock);
    int returned = file_write(target_file, buffer, size);
    lock_release(&files_sync_lock);
    return returned;
  }
}

void 
seek (int fd, unsigned position)
{
  struct file *file = get_target_file(fd);
  if(file == NULL) return;
  lock_acquire (&files_sync_lock);
  file_seek(file, position);
  lock_release (&files_sync_lock);
}

unsigned 
tell (int fd)
{
  struct file *file = get_target_file(fd);
  if(file == NULL) return -1;
  lock_acquire (&files_sync_lock);
  file_tell(file);
  lock_release (&files_sync_lock);
}

void 
close (int fd)
{
  if (fd == 1 || fd == 0) return;
  struct list_elem *fileelm = get_target_fileelem(fd);
  if (fileelm == NULL) return;
  struct open_file *file = list_entry(fileelm, struct open_file, fileelem);
  lock_acquire (&files_sync_lock);
  file_close (file->ptr);
  list_remove (&file->fileelem);
  free (file);
  lock_release (&files_sync_lock);
}

/* SOME AUXILLARY FUNCTIONS */

struct list_elem 
*get_target_fileelem (int fd)
{
  struct list_elem *e = list_head(&thread_current()->open_files);
  while (e != list_tail(&thread_current()->open_files))
  {
    e = list_next(e);
    struct open_file *file = list_entry(e, struct open_file, fileelem);
    if (file->fd == fd) return e;
  }

  return NULL;
}
 
void 
validate_void_ptr (void * ptr)
{
  if (ptr == NULL || !is_user_vaddr (ptr) || pagedir_get_page(thread_current()->pagedir,ptr) == NULL)
  {
    if(lock_held_by_current_thread(&files_sync_lock))
      lock_release (&files_sync_lock);
    exit (-1);
  }
}

struct file 
*get_target_file (int fd)
{
  struct thread *current_thread = thread_current ();
  struct list_elem *e = list_head(&thread_current()->open_files);
  struct list *open_list = &thread_current()->open_files;
  struct file *target_file = NULL;
  while (e != list_tail(&thread_current()->open_files))
  {
    e = list_next(e);
    struct open_file *file = list_entry(e, struct open_file, fileelem);
    if (file->fd == fd)
    {
      target_file = file->ptr;
      break;
    }
  }
  return target_file;
}