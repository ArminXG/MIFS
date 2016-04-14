/*
  MIFS - Multifile Image File System
  Copyright (C) 2016 Armin Schindler

  This program can be distributed under the terms of the GNU GPLv3.
  See the file LICENSE.
*/

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <pthread.h>

#define MIFS_VERSION "0.9"

#define DEFAULTNAME "mifs"

#define BLOCKSIZE 4096
#define FPERDIR 256

#define FILECACHEMAX 32

struct mifs_filecache_s {
	int active;
	int write;
	unsigned long long int filenumber;
	pthread_mutex_t mutex;
	char fullfilename[4096];
	char *buf;
};
static struct mifs_filecache_s filecache[FILECACHEMAX];
static int last_filecache;
static pthread_mutex_t filecache_mutex = PTHREAD_MUTEX_INITIALIZER;

struct mifs_s {
	char *name;
	char *size;
	char *filesizestring;
	char *path;
	unsigned long long filesize;
	unsigned int filecount;
	unsigned int filesperdir;
	unsigned int subdirs;
	unsigned int sha256;
	struct stat st;
	struct stat dirst;
};

static struct mifs_s mifs;

#define MAXNAMELEN 1024
struct mifs_file_s {
	int active;
	int error;
	unsigned long long int filenumber;
	char path[MAXNAMELEN];
	char filename[MAXNAMELEN];
	off_t offset;
	size_t size;
	off_t offset_left;
	size_t size_left;
};

static struct fuse_context *fcontext;

/*
 * logging (debug)
 */
static FILE *logfile = NULL;

static void log_open()
{
	logfile = fopen("mifs.log", "w");
	/* set logfile to line buffering */
	setvbuf(logfile, NULL, _IOLBF, 0);
}

static void log_close()
{
	if (logfile) {
		fclose(logfile);
	}
	logfile = NULL;
}

static void log_msg(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);

	if (logfile != NULL) {
		vfprintf(logfile, format, ap);
	}
}

/*
 * helpers
 */
static unsigned long long int get_size_arg(char *s)
{
	unsigned long long int res = 0;
	char *p = NULL;
	static const char *suffixes = "bkmgt";
	int i = 0;

	if (s) {
		res = strtoull(s, &p, 0);
		if (s == p)
			return 0;
		if ((res) && (p)) {
			for (i = strlen(suffixes) - 1; i >= 0; i--)
				if (suffixes[i] == tolower((int) *p))
					break;
			while (i-- > 0)
				res *= 1024;
		}
	}

	return res;
}

static size_t gen_sha256(unsigned char *buffer, size_t len, size_t maxlen, int bin)
{
	unsigned char shabuf[SHA256_DIGEST_LENGTH];
	size_t ret = 0;
	SHA256_CTX ctx;

	if (((SHA256_DIGEST_LENGTH * 2) + 1) > maxlen) {
		return 0;
	}

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buffer, len);
	SHA256_Final(shabuf, &ctx);

	if (bin) {
		memcpy(buffer, shabuf, SHA256_DIGEST_LENGTH);
		return SHA256_DIGEST_LENGTH;
	}

	for (len = 0; len < SHA256_DIGEST_LENGTH; ++len)
		ret += sprintf(buffer + ret, "%02x", shabuf[len]);

	return ret;
}

static void set_filename(struct mifs_file_s *fls, unsigned long long int filenumber)
{
	unsigned char buf[8192];
	unsigned char nbuf[1024];
	int i;

	if (mifs.sha256) {
		i = snprintf(buf, sizeof(buf), "%s-%032llx", mifs.name, filenumber);
		strcpy(nbuf, buf);
		gen_sha256(buf, i, sizeof(buf), 0);
		snprintf(fls->filename, MAXNAMELEN, "%s", buf);
		log_msg("  file=%s , shaname=%s\n", nbuf, fls->filename);
	} else {
		snprintf(nbuf, sizeof(nbuf), "%08llx", filenumber);
		strcpy(fls->filename, nbuf);
		log_msg("  file=%s\n", fls->filename);
	}
}

static void set_path(struct mifs_file_s *fls)
{
	unsigned char nbuf[1024];
	int i = 0, j = 0, k;

	strcpy(nbuf, fls->filename);

	k = strlen(nbuf) - 1;

	while(i < mifs.subdirs) {
		fls->path[j++] = '/';
		fls->path[j++] = nbuf[k];
		k--;
		if (mifs.filesperdir > 16) {
			fls->path[j++] = nbuf[k];
			k--;
		}
		i++;
	}
}

static int next_part_file(struct mifs_file_s *fls, size_t size, off_t offset)
{
	unsigned long long int filenumber = 0;

	if (!fls->active) {
		/* initial call */
		fls->offset_left = offset;
		fls->size_left = size;
		fls->active = 1;
	} else {
		if (fls->size_left <= 0) {
			/* no more */
			return 0;
		}
	}

	if (fls->offset_left != 0) {
		filenumber = fls->offset_left / mifs.filesize;
	}
	if ((filenumber * mifs.filesize) >= mifs.st.st_size) {
		fls->error = -ENOSPC;
		return 1;
	}
	fls->filenumber = filenumber;

	fls->offset = fls->offset_left - (filenumber * mifs.filesize);

	if (fls->size_left > (mifs.filesize - fls->offset)) {
		fls->size = mifs.filesize - fls->offset;
	} else {
		fls->size = fls->size_left;
	}

	set_filename(fls, filenumber);
	set_path(fls);

	fls->size_left -= fls->size;
	fls->offset_left += fls->size;

	return 1;
}

static int check_and_do_access(char *path, char *dir, char *filename, int write)
{
	char buf[4096];
	char cdir[1024];
	char *p, *q;
	struct stat st;
	int pos;

	snprintf(buf, sizeof(buf), "%s%s/%s", path, dir, filename);

	if (!write) {
		return(access(buf, R_OK));
	}

	/* write */
	if (access(buf, W_OK) == 0)
		return 0;

	if (access(path, W_OK) != 0)
		return -1;

	if (strlen(dir) > 0) {
		pos = snprintf(buf, sizeof(buf), "%s", path);
		strncpy(cdir, dir, sizeof(cdir));
		p = cdir + 1;
		while (p && *p != 0) {
			q = strchr(p, '/');
			if (q != NULL) {
				*q = 0;
			}
			pos += snprintf(buf + pos, sizeof(buf) - pos, "/%s", p);
			if (q != NULL) {
				p = q + 1;
			} else {
				p = NULL;
			}
			if (stat(buf, &st) == 0) {
				if (S_ISDIR(st.st_mode)) {
					if (access(buf, W_OK) == 0)
						continue;
				}
			}
			log_msg("mkdir: %s\n", buf);
			if (mkdir(buf, 0755) != 0)
				return -1;
			if (access(buf, W_OK) != 0)
				return -1;
		}
	}

	return 0;
}

static void release_mifsfile(int i)
{
	int fd;
	int err;

	/* called with filecache lock held */
	if (filecache[i].write) {
		fd = open(filecache[i].fullfilename, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		err = errno;
		log_msg("release_mifsfile: write-fd=%d : %s\n", fd, filecache[i].fullfilename);
		if (fd >= 0) {
			if (write(fd, filecache[i].buf, mifs.filesize) != mifs.filesize) {
				log_msg("release_mifsfile: error writing filenumber: %08llx\n", filecache[i].filenumber);
			}
			close(fd);
		} else {
			log_msg("                  %s\n", strerror(err));
		}
	}
}

static void close_all_mifsfiles()
{
	int i;

	pthread_mutex_lock(&filecache_mutex);
	for (i = 0; i < FILECACHEMAX; i++) {
		if (filecache[i].active) {
			release_mifsfile(i);
			filecache[i].active = 0;
		}
	}
	pthread_mutex_unlock(&filecache_mutex);
}

static void close_mifsfile(int i)
{
	if ((i >= 0) && (i < FILECACHEMAX)) {
		pthread_mutex_unlock(&(filecache[i].mutex));
	}
}

static int open_mifsfile(int write, struct mifs_file_s *fls)
{
	int fd;
	int i = -1;
	size_t pos, posa;

	pthread_mutex_lock(&filecache_mutex);

	for (i = 0; i < FILECACHEMAX; i++) {
		if ((filecache[i].active) && (filecache[i].filenumber == fls->filenumber)) {
			if ((write) && (!(filecache[i].write))) {
				filecache[i].write = write;
			}
			pthread_mutex_unlock(&filecache_mutex);
			return i;
		}
	}
	if (i >= FILECACHEMAX) {
		for (i = 0; i < FILECACHEMAX; i++) {
			if (filecache[i].active == 0)
				break;
		}
		if (i >= FILECACHEMAX) {
			i = last_filecache;
			release_mifsfile(i);
			filecache[last_filecache].active = 0;
			last_filecache++;
			if (last_filecache >= FILECACHEMAX)
				last_filecache = 0;
		}
	}

	if (check_and_do_access(mifs.path, fls->path, fls->filename, write) == 0) {
		filecache[i].active = 1;
		filecache[i].filenumber = fls->filenumber;
		filecache[i].write = write;
		snprintf(filecache[i].fullfilename, sizeof(filecache[i].fullfilename), "%s%s/%s", mifs.path, fls->path, fls->filename);
		pos = 0;
		fd = open(filecache[i].fullfilename, O_RDONLY);
		log_msg("open_mifsfile: i=%d , fd=%d : %s : %s\n", i, fd, (fd < 0)?strerror(errno):"", filecache[i].fullfilename);
		if (fd >= 0) {
			while((posa = read(fd, filecache[i].buf + pos, mifs.filesize)) > 0) {
				log_msg("open_mifsfile: initial read fd=%d , pos=%llu\n", fd, pos);
				pos += posa;
				if (pos >= mifs.filesize)
					break;
			}
			close(fd);
		}
		if (pos < 0) pos = 0;
		if (pos != mifs.filesize) {
			memset(filecache[i].buf + pos, 0, mifs.filesize - pos);
		}
		pthread_mutex_lock(&(filecache[i].mutex));
	} else {
		i = -1;
	}

	pthread_mutex_unlock(&filecache_mutex);

	return i;
}

static size_t read_mifsfile(struct mifs_file_s *fls, void *buf, size_t count, off_t offset)
{
	int i;

	i = open_mifsfile(0, fls);
	if (i < 0) {
		memset(buf, 0, count);
		log_msg("read_mifsfile: error open_mifsfile, return zeroed buffer.\n");
	} else {
		memcpy(buf, filecache[i].buf + offset, count);
	}
	close_mifsfile(i);

	return count;
}

static size_t write_mifsfile(struct mifs_file_s *fls, void *buf, size_t count, off_t offset)
{
	int i;

	i = open_mifsfile(1, fls);
	if (i < 0) {
		log_msg("write_mifsfile: error open_mifsfile\n");
		return -EIO;
	}
	memcpy(filecache[i].buf + offset, buf, count);

	close_mifsfile(i);

	return count;
}

/*
 * fs functions
 */
static void *mifs_init(struct fuse_conn_info *conn)
{
	log_msg("mifs_init\n");

	return NULL;
}

static void mifs_destroy(void *userdata)
{
	log_msg("mifs_destroy\n");
}

static int mifs_open(const char *path, struct fuse_file_info *fi)
{
	log_msg("mifs_open(path=%s , flags=%x)\n", path, fi->flags);

	if (strcmp(path + 1, mifs.name) != 0)
		return -ENOENT;

	return 0;
}

static int mifs_flush(const char *path, struct fuse_file_info *fi)
{
	log_msg("mifs_flush(path=%s)\n", path);

	return 0;
}

static int mifs_release(const char *path, struct fuse_file_info *fi)
{
	int ret = 0;

	log_msg("mifs_release(path=%s)\n", path);

	close_all_mifsfiles();

	return ret;
}

static int mifs_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
	int ret = 0;

	log_msg("mifs_fsync(path=%s)\n", path);

	if (strcmp(path + 1, mifs.name) != 0)
		return -ENOENT;

	close_all_mifsfiles();

	return ret;
}

static int mifs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	int ret = 0;
	int fd;
	int good;
	off_t of;
	size_t rb;
	struct mifs_file_s filestatus;

	log_msg("mifs_read(path=%s , size=%llu , offset=%llu)\n", path, size, offset);

	if (strcmp(path + 1, mifs.name) != 0)
		return -ENOENT;

	memset(&filestatus, 0, sizeof(filestatus));
	while (next_part_file(&filestatus, size, offset)) {	
		if (filestatus.error != 0) {
			return 0;
		}
		log_msg("     read(path=%s%s/%s , size=%llu , offset=%llu)\n",
			mifs.path, filestatus.path, filestatus.filename, filestatus.size, filestatus.offset);
		rb = read_mifsfile(&filestatus, buf + ret, filestatus.size, filestatus.offset);
		if (rb != filestatus.size) {
			ret = rb;
			break;
		}
		ret += filestatus.size;
	}
	if (ret != size) {
		log_msg("mifs_read(ret=%d)\n", ret);
	}

	return ret;
}

static int mifs_write(const char *path, const char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
	int ret = 0;
	int fd;
	off_t of;
	size_t rb;
	int good;
	struct mifs_file_s filestatus;

	log_msg("mifs_write(path=%s , size=%llu , offset=%llu)\n", path, size, offset);

	if (strcmp(path + 1, mifs.name) != 0)
		return -ENOENT;

	memset(&filestatus, 0, sizeof(filestatus));
	while ((ret >= 0) && (next_part_file(&filestatus, size, offset))) {	
		if (filestatus.error != 0) {
			ret = filestatus.error;
			break;
		}
		log_msg("     write(path=%s%s/%s , size=%llu , offset=%llu)\n",
			mifs.path, filestatus.path, filestatus.filename, filestatus.size, filestatus.offset);
		rb = write_mifsfile(&filestatus, (char *)buf + ret, filestatus.size, filestatus.offset);
		if (rb != filestatus.size) {
			ret = -EIO;
			break;
		}
		ret += filestatus.size;
	}
	if (ret != size) {
		log_msg("mifs_write(ret=%d)\n", ret);
	}

	return ret;
}

static int mifs_getattr(const char *path, struct stat *statbuf)
{
	int ret = 0;

	log_msg("mifs_getattr(path=%s)\n", path);

	if (strcmp(path, "/") == 0) {
		memcpy(statbuf, &mifs.dirst, sizeof(struct stat));
	} else if (strcmp(path + 1, mifs.name) == 0) {
		memcpy(statbuf, &mifs.st, sizeof(struct stat));
	} else {
		ret = -ENOENT;
	}

	return ret;
}

static int mifs_utime(const char *path, struct utimbuf *ubuf)
{
	int ret = -ENOENT;

	log_msg("mifs_utime(path=%s)\n", path);

	if (strcmp(path + 1, mifs.name) == 0) {
		mifs.st.st_atime = ubuf->actime;
		mifs.st.st_mtime = ubuf->modtime;
		mifs.st.st_ctime = ubuf->modtime;
		mifs.dirst.st_atime = ubuf->actime;
		mifs.dirst.st_mtime = ubuf->modtime;
		mifs.dirst.st_ctime = ubuf->modtime;
		ret = 0;
	}

	return ret;
}

/*
static int mifs_statfs(const char *path, struct statvfs *statv)
{
	int ret = 0;

	log_msg("mifs_statfs(path=%s)\n", path);
	// TODO return fs stat faked

	return ret;
}
*/

static int mifs_access(const char *path, int mask)
{
	int ret = 0;

	log_msg("mifs_access(path=%s)\n", path);

	if ((strcmp(path, "/") != 0) && (strcmp(path + 1, mifs.name) != 0)) {
		ret = -ENOENT;
	}

	return ret;
}

/*
static int mifs_readlink(const char *path, char *link, size_t size)
{
	int ret = 0;

	log_msg("mifs_readlink(path=%s)\n", path);

	return ret;
}
*/

static int mifs_truncate(const char *path, off_t newsize)
{
	log_msg("mifs_truncate(path=%s)\n", path);

	if (strcmp(path + 1, mifs.name) != 0)
		return -ENOENT;

	return 0;
}

static int mifs_ftruncate(const char *path, off_t offset, struct fuse_file_info *fi)
{
	log_msg("mifs_ftruncate(path=%s)\n", path);

	if (strcmp(path + 1, mifs.name) != 0)
		return -ENOENT;

	return 0;
}

static int mifs_fgetattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi)
{
	int ret = 0;

	log_msg("mifs_fgetattr(path=%s)\n", path);

	ret = mifs_getattr(path, statbuf);

	return ret;
}

/*
static int mifs_opendir(const char *path, struct fuse_file_info *fi)
{
	int ret = 0;

	log_msg("mifs_opendir(path=%s)\n", path);

	return ret;
}
*/

static int mifs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
		struct fuse_file_info *fi)
{
	int ret = 0;

	log_msg("mifs_readdir(path=%s)\n", path);

	if (strcmp(path, "/") != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	filler(buf, mifs.name, NULL, 0);

	return ret;
}

/*
static int mifs_releasedir(const char *path, struct fuse_file_info *fi)
{
	int ret = 0;

	log_msg("mifs_releasedir(path=%s)\n", path);

	return ret;
}
*/

/*
static int mifs_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{
	int ret = 0;

	log_msg("mifs_fsyncdir(path=%s)\n", path);

	return ret;
}
*/

static struct fuse_operations mifs_oper = {
	.init       = mifs_init,
	.destroy    = mifs_destroy,
	.open       = mifs_open,
	.flush      = mifs_flush,
	.release    = mifs_release,
	.fsync      = mifs_fsync,
	.read       = mifs_read,
	.write      = mifs_write,
	.getattr    = mifs_getattr,
	.utime      = mifs_utime,
	.access     = mifs_access,
	.truncate   = mifs_truncate,
	.ftruncate  = mifs_ftruncate,
	.fgetattr   = mifs_fgetattr,
	.readdir    = mifs_readdir,

# if 0
	/* we don't use these functions */
	.statfs     = mifs_statfs,
	.readlink   = mifs_readlink,
	.opendir    = mifs_opendir,
	.releasedir = mifs_releasedir,
	.fsyncdir   = mifs_fsyncdir,

	.getdir     =
	.mknod      =
	.mkdir      =
	.symlink    =
	.unlink     =
	.rmdir      =
	.rename     =
	.link       =
	.chmod      =
	.chown      =
	.create     =

#if HAVE_XATTR
	.setxattr   =
	.getxattr   =
	.listxattr  =
	.removexattr =
#endif

#endif
};

enum {
	KEY_VERSION,
	KEY_HELP,
	KEY_LOG,
	KEY_FPERDIR,
	KEY_SHA256,
};

#define MIFS_OPT(t, p, v) { t, offsetof(struct mifs_s, p), v }

static struct fuse_opt mifs_opts[] = {
	MIFS_OPT("-n %s",              name, 0),
	MIFS_OPT("-S %s",              size, 0),
	MIFS_OPT("-p %s",              path, 0),
	MIFS_OPT("-b %s",              filesizestring, 0),
	FUSE_OPT_KEY("-16",            KEY_FPERDIR),
	FUSE_OPT_KEY("-sha256",        KEY_SHA256),
	FUSE_OPT_KEY("-L",             KEY_LOG),
	FUSE_OPT_KEY("-V",             KEY_VERSION),
	FUSE_OPT_KEY("--version",      KEY_VERSION),
	FUSE_OPT_KEY("-h",             KEY_HELP),
	FUSE_OPT_KEY("--help",         KEY_HELP),
	FUSE_OPT_END
};

static void usage(const char *progname)
{
	printf(
"usage: %s mountpoint [options]\n"
"\n"
"general options:\n"
"    -o opt,[opt...]        mount options\n"
"    -n <name>              image filename\n"
"    -S <size>[kKmMgG]      size of image file\n"
"    -p <path>              path to store block files\n"
"    -b <size>[kKmMgG]      size of block files\n"
"    -16                    16 files per subdir (default 256)\n"
"    -sha256                use sha256 hashed block file names\n"
"    -h   --help            print help\n"
"    -V   --version         print version\n"
"    -L                     enable debug log to ./mifs.log\n"
"\n", progname);
}

static int mifs_opt_proc(void *data, const char *arg, int key,
                           struct fuse_args *outargs)
{
	switch(key) {
	case KEY_FPERDIR:
		mifs.filesperdir = 16;
		return 0;

	case KEY_SHA256:
		mifs.sha256 = 1;
		return 0;

	case KEY_LOG:
		log_open();
		log_msg("START\n");
		return 0;

	case KEY_HELP:
		usage(outargs->argv[0]);
		fuse_opt_add_arg(outargs, "-ho");
		fuse_main(outargs->argc, outargs->argv, &mifs_oper, NULL);
		exit(1);

	case KEY_VERSION:
		printf("MIFS version: %s\n", MIFS_VERSION);
		fuse_opt_add_arg(outargs, "--version");
		fuse_main(outargs->argc, outargs->argv, &mifs_oper, NULL);
		exit(0);
	}
	return 1;
}

int main(int argc, char *argv[])
{
	int fuse_stat;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	time_t now = time(NULL);
	struct stat pstat;
	int i;

	fcontext = fuse_get_context();

	mifs.name = DEFAULTNAME;
	mifs.filesperdir = FPERDIR;

	mifs.st.st_nlink = 1;
	mifs.st.st_mode = S_IFREG | 0644;
	mifs.st.st_uid = fcontext->uid;
	mifs.st.st_gid = fcontext->gid;
	mifs.st.st_atime = now;
	mifs.st.st_mtime = now;
	mifs.st.st_ctime = now;

	memcpy(&mifs.dirst, &mifs.st, sizeof(struct stat));
	mifs.dirst.st_nlink = 2;
	mifs.dirst.st_mode = S_IFDIR | 0755;

	if (fuse_opt_parse(&args, &mifs, mifs_opts, mifs_opt_proc) == -1) {
		perror("parse options");
		abort();
	}

	if (mifs.path == NULL) {
		printf("Missing path to store block files!\n");
		exit(1);
	}
	if ((stat(mifs.path, &pstat) != 0)  || (!S_ISDIR(pstat.st_mode))) {
		printf("Path to store block files is not a valid directory!\n");
		exit(1);
	}
	log_msg("Path set to: %s\n", mifs.path);

	log_msg("Name set to: %s\n", mifs.name);

	log_msg("Files per dir set to %d\n", mifs.filesperdir);

	mifs.filesize = get_size_arg(mifs.filesizestring);
	if (mifs.filesize == 0)
		mifs.filesize = BLOCKSIZE;
	mifs.filesize = (mifs.filesize / BLOCKSIZE) * BLOCKSIZE;
	log_msg("Filesize set to: %llu\n", mifs.filesize);

	mifs.st.st_size = (off_t)get_size_arg(mifs.size);
	if (mifs.st.st_size < mifs.filesize)
		mifs.st.st_size = mifs.filesize;
	mifs.st.st_size = (mifs.st.st_size / BLOCKSIZE) * BLOCKSIZE;
	log_msg("Size set to: %llu\n", mifs.st.st_size);

	mifs.filecount = mifs.st.st_size / mifs.filesize;

	mifs.subdirs = 0;
	i = mifs.filecount;
	while (i > mifs.filesperdir) {
		mifs.subdirs++;
		i /= mifs.filesperdir;
	}
	log_msg("Subdirs set to: %d\n", mifs.subdirs);

	for (i = 0; i < FILECACHEMAX; i++) {
		pthread_mutex_init(&(filecache[i].mutex), NULL );
		filecache[i].buf = malloc(mifs.filesize);
		if (filecache[i].buf == NULL) {
			printf("Error, cannot alloc cache memory!\n");
			exit(1);
		}
	}

	fuse_stat = fuse_main(args.argc, args.argv, &mifs_oper, NULL);

	log_msg("END\n");
	log_close();

	for (i = 0; i < FILECACHEMAX; i++) {
		if (filecache[i].buf != NULL) {
			free(filecache[i].buf);
		}
	}

	return fuse_stat;
}


