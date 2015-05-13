#ifndef BITCOIN_PARSE_IO_H
#define BITCOIN_PARSE_IO_H
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
/* These functions all exit on errors. */

/* We save the name for error reporting. */
struct file {
	const char *name;
	int fd;
	off_t len;
	void *mmap;
};

/* O_NOCTTY doesn't make sense for normal files, so overload it */
#define O_NO_MMAP O_NOCTTY

/* Just return mmap pointer, or read into buffer and return that. */
void *file_read(struct file *f, off_t off, size_t size, void *buf);

/* Write back if not mmaped. */
void file_write(struct file *f, off_t off, size_t size, const void *buf);

/* Append to end of file.  Assumes we're the only ones modifying size! */
void file_append(struct file *f, const void *buf, size_t size);

/* Open file (perm 0600 if O_CREAT), truncate to len if != 0 */
void file_open(struct file *f, const char *name, off_t len, int oflags);

void file_close(struct file *f);
#endif /* BITCOIN_PARSE_IO_H */
