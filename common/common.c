#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>

int find_fd_seccomp_notifier(const char *path)
{
	char entry[2 * PATH_MAX + 1];
	char buf[PATH_MAX + 1];
	struct dirent *dp;
	ssize_t nbytes;
	struct stat sb;
	DIR *dirp;

	if ((dirp = opendir(path)) == NULL) {
		fprintf(stderr, "failed reading fds from proc: %s \n", path);
		return -1;
	}
	while ((dp = readdir(dirp)) != NULL) {
		snprintf(entry, sizeof(entry), "%s/%s", path, dp->d_name);
		if (lstat(entry, &sb) == -1) {
			perror("lstat");
		}
		/* Skip the entry if it isn't a symbolic link */
		if (!S_ISLNK(sb.st_mode))
			continue;

		nbytes = readlink(entry, buf, PATH_MAX);
		if (nbytes == -1) {
			perror("readlink");
		}
		if (nbytes == PATH_MAX) {
			perror("buffer overflow");
			continue;
		}
		/*
                 * From man proc: For  file  descriptors  that  have no
                 * corresponding inode (e.g., file descriptors produced by
                 * bpf(2)..), the  entry  will be a symbolic link with contents
                 * of the form:
                 *      anon_inode:<file-type>
                 */
		if (strstr(buf, "anon_inode:seccomp notify") != NULL)
			return atoi(dp->d_name);
	}
	fprintf(stderr, "seccomp notifier not found in %s\n", path);
	return -1;
}
