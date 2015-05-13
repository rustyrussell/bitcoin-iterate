#include <ccan/err/err.h>
#include "io.h"
#include <stdbool.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mman.h>

void *file_read(struct file *f, off_t off, size_t size, void *buf)
{
	if (f->mmap) {
		assert(off + size <= f->len);
		return f->mmap + off;
	}
	if (pread(f->fd, buf, size, off) != size)
		err(1, "Reading %zu from %s offset %llu",
		    size, f->name, (long long)off);
	return buf;
}

void file_write(struct file *f, off_t off, size_t size, const void *buf)
{
	if (f->mmap) {
		assert(off + size <= f->len);
		return;
	}

	if (pwrite(f->fd, buf, size, off) != size)
		err(1, "Writing %zu to %s offset %llu",
		    size, f->name, (long long)off);
}

void file_append(struct file *f, const void *buf, size_t size)
{
	bool mapped = f->mmap;

	if (mapped) {
		munmap(f->mmap, f->len);
		f->mmap = NULL;
	}

	if (pwrite(f->fd, buf, size, f->len) != size)
		err(1, "Appending %zu to %s", size, f->name);
	f->len += size;

	if (mapped) {
		f->mmap = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED,
			       f->fd, 0);
		if (f->mmap == MAP_FAILED)
			f->mmap = NULL;
	}
}

void file_open(struct file *f, const char *name, off_t len, int oflags)
{
	int protflags;
	struct stat st;
	off_t size;
	bool do_mmap = !(oflags & O_NO_MMAP);

	f->name = name;
	f->fd = open(name, oflags & ~O_NO_MMAP, 0600);
	if (f->fd < 0)
		err(1, "Opening %s", name);

	if ((oflags & O_ACCMODE) == O_RDONLY)
		protflags = PROT_READ;
	else
		protflags = PROT_READ|PROT_WRITE;

	if (len) {
		char bytes[4096];

		if (ftruncate(f->fd, len) != 0)
			err(1, "Truncating %s to %llu", name, (long long)len);

		/* Fill with bytes: we don't want hashfiles non-linear. */
		lseek(f->fd, 0, SEEK_SET);
		while (len > sizeof(bytes)) {
			if (write(f->fd, bytes, sizeof(bytes)) != sizeof(bytes))
				err(1, "Writing %s out to %llu",
				    name, (long long)len);
			len -= sizeof(bytes);
		}
	}

	if (fstat(f->fd, &st) != 0)
		err(1, "Statting %s", name);

	f->len = st.st_size;
	if (do_mmap) {
		size = ((f->len + getpagesize()-1) & ~(getpagesize()-(off_t)1));
		f->mmap = mmap(NULL, size, protflags, MAP_SHARED, f->fd, 0);
		if (f->mmap == MAP_FAILED)
			f->mmap = NULL;
	} else
		f->mmap = NULL;

}

void file_close(struct file *f)
{
	if (f->mmap)
		munmap(f->mmap, f->len);
	close(f->fd);
	f->fd = -1;
}
