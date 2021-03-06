UNIFYCR_DEF(access, int, (const char *path, int mode));
UNIFYCR_DEF(mkdir, int, (const char *path, mode_t mode));
UNIFYCR_DEF(rmdir, int, (const char *path));
UNIFYCR_DEF(rename, int, (const char *oldpath, const char *newpath));
UNIFYCR_DEF(truncate, int, (const char* path, off_t length));
UNIFYCR_DEF(unlink, int, (const char *path));
UNIFYCR_DEF(remove, int, (const char *path));
UNIFYCR_DEF(stat, int, (const char *path, struct stat *buf));
UNIFYCR_DEF(__xstat, int, (int vers, const char *path, struct stat *buf));
UNIFYCR_DEF(__lxstat, int, (int vers, const char *path, struct stat *buf));
UNIFYCR_DEF(statfs, int, (const char *path, struct statfs *buf));
UNIFYCR_DEF(realpath, char*, (const char* path, char* buf));
UNIFYCR_DEF(__realpath_chk, char*, (const char* path, char* buf, size_t size));
UNIFYCR_DEF(creat, int, (const char* path, mode_t mode));
UNIFYCR_DEF(creat64, int, (const char* path, mode_t mode));
UNIFYCR_DEF(open, int, (const char *path, int flags, ...));
UNIFYCR_DEF(__open_2, int, (const char *path, int flags));
UNIFYCR_DEF(open64, int, (const char* path, int flags, ...));
UNIFYCR_DEF(lseek, off_t, (int fd, off_t offset, int whence));
UNIFYCR_DEF(lseek64, off64_t, (int fd, off64_t offset, int whence));
UNIFYCR_DEF(posix_fadvise, int, (int fd, off_t offset, off_t len, int advice));
UNIFYCR_DEF(read, ssize_t, (int fd, void *buf, size_t count));
UNIFYCR_DEF(write, ssize_t, (int fd, const void *buf, size_t count));
UNIFYCR_DEF(readv, ssize_t, (int fd, const struct iovec *iov, int iovcnt));
UNIFYCR_DEF(writev, ssize_t, (int fd, const struct iovec *iov, int iovcnt));
UNIFYCR_DEF(pread, ssize_t, (int fd, void *buf, size_t count, off_t offset));
UNIFYCR_DEF(pread64, ssize_t, (int fd, void *buf, size_t count, off64_t offset));
UNIFYCR_DEF(pwrite, ssize_t, (int fd, const void *buf, size_t count, off_t offset));
UNIFYCR_DEF(pwrite64, ssize_t, (int fd, const void *buf, size_t count, off64_t offset));
UNIFYCR_DEF(ftruncate, int, (int fd, off_t length));
UNIFYCR_DEF(fsync, int, (int fd));
UNIFYCR_DEF(fdatasync, int, (int fd));
UNIFYCR_DEF(flock, int, (int fd, int operation));
UNIFYCR_DEF(mmap, void*, (void *addr, size_t length, int prot, int flags, int fd, off_t offset));
UNIFYCR_DEF(munmap, int, (void *addr, size_t length));
UNIFYCR_DEF(msync, int, (void *addr, size_t length, int flags));
UNIFYCR_DEF(mmap64, void*, (void *addr, size_t length, int prot, int flags, int fd, off_t offset));
UNIFYCR_DEF(__fxstat, int, (int vers, int fd, struct stat *buf));
UNIFYCR_DEF(close, int, (int fd));
UNIFYCR_DEF(fopen, FILE*, (const char *path, const char *mode));
UNIFYCR_DEF(freopen, FILE*, (const char *path, const char *mode, FILE *stream));
UNIFYCR_DEF(setvbuf, int, (FILE* stream, char* buf, int type, size_t size));
UNIFYCR_DEF(setbuf, void, (FILE* stream, char* buf));
UNIFYCR_DEF(ungetc, int, (int c, FILE *stream));
UNIFYCR_DEF(fgetc, int, (FILE *stream));
UNIFYCR_DEF(fputc, int, (int c, FILE *stream));
UNIFYCR_DEF(getc, int, (FILE *stream));
UNIFYCR_DEF(putc, int, (int c, FILE *stream));
UNIFYCR_DEF(fgets, char*, (char* s, int n, FILE* stream));
UNIFYCR_DEF(fputs, int, (const char* s, FILE* stream));
UNIFYCR_DEF(fread, size_t, (void *ptr, size_t size, size_t nitems, FILE *stream));
UNIFYCR_DEF(fwrite, size_t, (const void *ptr, size_t size, size_t nitems, FILE *stream));
UNIFYCR_DEF(fseek, int, (FILE *stream, long offset, int whence));
UNIFYCR_DEF(fseeko, int, (FILE *stream, off_t offset, int whence));
UNIFYCR_DEF(ftell, long, (FILE *stream));
UNIFYCR_DEF(ftello, off_t, (FILE *stream));
UNIFYCR_DEF(rewind, void, (FILE* stream));
UNIFYCR_DEF(fgetpos, int, (FILE* stream, fpos_t* pos));
UNIFYCR_DEF(fsetpos, int, (FILE* stream, const fpos_t* pos));
UNIFYCR_DEF(fflush, int, (FILE* stream));
UNIFYCR_DEF(feof, int, (FILE *stream));
UNIFYCR_DEF(ferror, int, (FILE* stream));
UNIFYCR_DEF(clearerr, void, (FILE* stream));
UNIFYCR_DEF(fileno, int, (FILE *stream));
UNIFYCR_DEF(fclose, int, (FILE *stream));
UNIFYCR_DEF(fwprintf, int, (FILE *stream, const wchar_t* format, ...));
UNIFYCR_DEF(fwscanf, int, (FILE *stream, const wchar_t* format, ...));
UNIFYCR_DEF(vfwprintf, int, (FILE *stream, const wchar_t* format, va_list arg));
UNIFYCR_DEF(vfwscanf, int, (FILE *stream, const wchar_t* format, va_list arg));
UNIFYCR_DEF(fgetwc, wint_t, (FILE *stream));
UNIFYCR_DEF(fgetws, wchar_t*, (wchar_t* s, int n, FILE *stream));
UNIFYCR_DEF(fputwc, wint_t, (wchar_t wc, FILE *stream));
UNIFYCR_DEF(fputws, int, (const wchar_t* s, FILE *stream));
UNIFYCR_DEF(fwide, int, (FILE *stream, int mode));
UNIFYCR_DEF(getwc, wint_t, (FILE *stream));
UNIFYCR_DEF(putwc, wint_t, (wchar_t c, FILE *stream));
UNIFYCR_DEF(ungetwc, wint_t, (wint_t c, FILE *stream));
struct gotcha_binding_t wrap_unifycr_list[] = {
	{ "access", UNIFYCR_WRAP(access), &UNIFYCR_REAL(access) },
	{ "mkdir", UNIFYCR_WRAP(mkdir), &UNIFYCR_REAL(mkdir) },
	{ "rmdir", UNIFYCR_WRAP(rmdir), &UNIFYCR_REAL(rmdir) },
	{ "rename", UNIFYCR_WRAP(rename), &UNIFYCR_REAL(rename) },
	{ "truncate", UNIFYCR_WRAP(truncate), &UNIFYCR_REAL(truncate) },
	{ "unlink", UNIFYCR_WRAP(unlink), &UNIFYCR_REAL(unlink) },
	{ "remove", UNIFYCR_WRAP(remove), &UNIFYCR_REAL(remove) },
	{ "stat", UNIFYCR_WRAP(stat), &UNIFYCR_REAL(stat) },
	{ "__xstat", UNIFYCR_WRAP(__xstat), &UNIFYCR_REAL(__xstat) },
	{ "__lxstat", UNIFYCR_WRAP(__lxstat), &UNIFYCR_REAL(__lxstat) },
	{ "statfs", UNIFYCR_WRAP(statfs), &UNIFYCR_REAL(statfs) },
	{ "realpath", UNIFYCR_WRAP(realpath), &UNIFYCR_REAL(realpath) },
	{ "__realpath_chk", UNIFYCR_WRAP(__realpath_chk), &UNIFYCR_REAL(__realpath_chk) },
	{ "creat", UNIFYCR_WRAP(creat), &UNIFYCR_REAL(creat) },
	{ "creat64", UNIFYCR_WRAP(creat64), &UNIFYCR_REAL(creat64) },
	{ "open", UNIFYCR_WRAP(open), &UNIFYCR_REAL(open) },
	{ "__open_2", UNIFYCR_WRAP(__open_2), &UNIFYCR_REAL(__open_2) },
	{ "open64", UNIFYCR_WRAP(open64), &UNIFYCR_REAL(open64) },
	{ "lseek", UNIFYCR_WRAP(lseek), &UNIFYCR_REAL(lseek) },
	{ "lseek64", UNIFYCR_WRAP(lseek64), &UNIFYCR_REAL(lseek64) },
	{ "posix_fadvise", UNIFYCR_WRAP(posix_fadvise), &UNIFYCR_REAL(posix_fadvise) },
	{ "read", UNIFYCR_WRAP(read), &UNIFYCR_REAL(read) },
	{ "write", UNIFYCR_WRAP(write), &UNIFYCR_REAL(write) },
	{ "readv", UNIFYCR_WRAP(readv), &UNIFYCR_REAL(readv) },
	{ "writev", UNIFYCR_WRAP(writev), &UNIFYCR_REAL(writev) },
	{ "pread", UNIFYCR_WRAP(pread), &UNIFYCR_REAL(pread) },
	{ "pread64", UNIFYCR_WRAP(pread64), &UNIFYCR_REAL(pread64) },
	{ "pwrite", UNIFYCR_WRAP(pwrite), &UNIFYCR_REAL(pwrite) },
	{ "pwrite64", UNIFYCR_WRAP(pwrite64), &UNIFYCR_REAL(pwrite64) },
	{ "ftruncate", UNIFYCR_WRAP(ftruncate), &UNIFYCR_REAL(ftruncate) },
	{ "fsync", UNIFYCR_WRAP(fsync), &UNIFYCR_REAL(fsync) },
	{ "fdatasync", UNIFYCR_WRAP(fdatasync), &UNIFYCR_REAL(fdatasync) },
	{ "flock", UNIFYCR_WRAP(flock), &UNIFYCR_REAL(flock) },
	{ "mmap", UNIFYCR_WRAP(mmap), &UNIFYCR_REAL(mmap) },
	{ "msync", UNIFYCR_WRAP(msync), &UNIFYCR_REAL(msync) },
	{ "mmap64", UNIFYCR_WRAP(mmap64), &UNIFYCR_REAL(mmap64) },
	{ "__fxstat", UNIFYCR_WRAP(__fxstat), &UNIFYCR_REAL(__fxstat) },
	{ "close", UNIFYCR_WRAP(close), &UNIFYCR_REAL(close) },
	{ "fopen", UNIFYCR_WRAP(fopen), &UNIFYCR_REAL(fopen) },
	{ "freopen", UNIFYCR_WRAP(freopen), &UNIFYCR_REAL(freopen) },
	{ "setvbuf", UNIFYCR_WRAP(setvbuf), &UNIFYCR_REAL(setvbuf) },
	{ "setbuf", UNIFYCR_WRAP(setbuf), &UNIFYCR_REAL(setbuf) },
	{ "ungetc", UNIFYCR_WRAP(ungetc), &UNIFYCR_REAL(ungetc) },
	{ "fgetc", UNIFYCR_WRAP(fgetc), &UNIFYCR_REAL(fgetc) },
	{ "fputc", UNIFYCR_WRAP(fputc), &UNIFYCR_REAL(fputc) },
	{ "getc", UNIFYCR_WRAP(getc), &UNIFYCR_REAL(getc) },
	{ "putc", UNIFYCR_WRAP(putc), &UNIFYCR_REAL(putc) },
	{ "fgets", UNIFYCR_WRAP(fgets), &UNIFYCR_REAL(fgets) },
	{ "fputs", UNIFYCR_WRAP(fputs), &UNIFYCR_REAL(fputs) },
	{ "fread", UNIFYCR_WRAP(fread), &UNIFYCR_REAL(fread) },
	{ "fwrite", UNIFYCR_WRAP(fwrite), &UNIFYCR_REAL(fwrite) },
	{ "fseek", UNIFYCR_WRAP(fseek), &UNIFYCR_REAL(fseek) },
	{ "fseeko", UNIFYCR_WRAP(fseeko), &UNIFYCR_REAL(fseeko) },
	{ "ftell", UNIFYCR_WRAP(ftell), &UNIFYCR_REAL(ftell) },
	{ "ftello", UNIFYCR_WRAP(ftello), &UNIFYCR_REAL(ftello) },
	{ "rewind", UNIFYCR_WRAP(rewind), &UNIFYCR_REAL(rewind) },
	{ "fgetpos", UNIFYCR_WRAP(fgetpos), &UNIFYCR_REAL(fgetpos) },
	{ "fsetpos", UNIFYCR_WRAP(fsetpos), &UNIFYCR_REAL(fsetpos) },
	{ "fflush", UNIFYCR_WRAP(fflush), &UNIFYCR_REAL(fflush) },
	{ "feof", UNIFYCR_WRAP(feof), &UNIFYCR_REAL(feof) },
	{ "ferror", UNIFYCR_WRAP(ferror), &UNIFYCR_REAL(ferror) },
	{ "clearerr", UNIFYCR_WRAP(clearerr), &UNIFYCR_REAL(clearerr) },
	{ "fileno", UNIFYCR_WRAP(fileno), &UNIFYCR_REAL(fileno) },
	{ "fclose", UNIFYCR_WRAP(fclose), &UNIFYCR_REAL(fclose) },
	{ "fwprintf", UNIFYCR_WRAP(fwprintf), &UNIFYCR_REAL(fwprintf) },
	{ "fwscanf", UNIFYCR_WRAP(fwscanf), &UNIFYCR_REAL(fwscanf) },
	{ "vfwprintf", UNIFYCR_WRAP(vfwprintf), &UNIFYCR_REAL(vfwprintf) },
	{ "vfwscanf", UNIFYCR_WRAP(vfwscanf), &UNIFYCR_REAL(vfwscanf) },
	{ "fgetwc", UNIFYCR_WRAP(fgetwc), &UNIFYCR_REAL(fgetwc) },
	{ "fgetws", UNIFYCR_WRAP(fgetws), &UNIFYCR_REAL(fgetws) },
	{ "fputwc", UNIFYCR_WRAP(fputwc), &UNIFYCR_REAL(fputwc) },
	{ "fputws", UNIFYCR_WRAP(fputws), &UNIFYCR_REAL(fputws) },
	{ "fwide", UNIFYCR_WRAP(fwide), &UNIFYCR_REAL(fwide) },
	{ "getwc", UNIFYCR_WRAP(getwc), &UNIFYCR_REAL(getwc) },
	{ "putwc", UNIFYCR_WRAP(putwc), &UNIFYCR_REAL(putwc) },
	{ "ungetwc", UNIFYCR_WRAP(ungetwc), &UNIFYCR_REAL(ungetwc) },
};

#define GOTCHA_NFUNCS (sizeof(wrap_unifycr_list) / sizeof(wrap_unifycr_list[0]))
