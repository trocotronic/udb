
#include <stdio.h>
#include <string.h>
int main() {
	FILE *fd = fopen("Changes", "r");
	FILE *fd2;
	char buf[1024];
	int i = 0, space = 0, j = 0;
	char releaseid[512];
	int generation = 0;
#ifdef UDB
	char udbid[512];
#endif

	if (!fd) {
		return -1;
	}

	while (fgets(buf, 1023, fd)) {
		if (!strstr(buf, "Changes,v"))
			continue;
		else {
			while (!isdigit(buf[i]))
				i++;
			j = i;
			while (buf[j]) {
				if (buf[j] == ' ')
					space++;
				if (space == 3) {
					buf[j] = 0;
					break;
				}
				j++;
			}
			strcpy(releaseid,&buf[i]);
		}
	}
	fclose(fd);
#ifdef UDB
	i = j = space = 0;
	
	if (!(fd = fopen("cambios.udb", "r")))
		return -1;
	while (fgets(buf, 1023, fd)) {
		if (!strstr(buf, "cambios.udb,v"))
			continue;
		else {
			while (!isdigit(buf[i]))
				i++;
			j = i;
			while (buf[j]) {
				if (buf[j] == ' ')
					space++;
				if (space == 3) {
					buf[j] = 0;
					break;
				}
				j++;
			}
			strcpy(udbid,&buf[i]);
		}
	}
#endif
	i = 0;
	fd = fopen("src/version.c", "r");
	if (!fd)
		generation = 1;
	else {
		while (fgets(buf, 1023, fd)) {
			if (!strstr(buf, "char *generation"))
				continue;
			while (!isdigit(buf[i]))
					i++;
			j = i;
			while (isdigit(buf[j])) 
				j++;
			buf[j] = 0;
			generation = (atoi(&buf[i])+1);
		}
	}
	fd = fopen("src/version.c.sh", "r");
	if (!fd)
		return 0;
	fd2 = fopen("src/version.c", "w");
	if (!fd2)
		return 0;
	while (fgets(buf, 1023, fd)) {
		if (!strncmp("cat >version.c <<!SUB!THIS!",buf,27)) {
			while (fgets(buf, 1023, fd)) {
				if (!strncmp("!SUB!THIS!",buf,10))
					break;
				if (!strncmp("char *creation = \"$creation\";",buf,29)) 
					fprintf(fd2,"char *creation = __TIMESTAMP__;\n");
				else if (!strncmp("char *generation = \"$generation\";",buf,33))
					fprintf(fd2,"char *generation = \"%d\";\n",generation);
				else if (!strncmp("char *buildid = \"$id\";",buf,22))
					fprintf(fd2,"char *buildid = \"%s\";\n",releaseid);
#ifdef UDB
				else if (!strncmp("char *udbid = \"$udbid\";",buf,22))
					fprintf(fd2,"char *udbid = \"%s\";\n",udbid);
#endif
				else
					fprintf(fd2,"%s", buf);
			}
		}
	}


}
	