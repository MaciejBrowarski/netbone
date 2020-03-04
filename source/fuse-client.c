
/*
 * FUSE client for IDS 
 * 0.0.1 2009 Jul - created (based on read-only FUSE)
 * 0.0.2 2009 Dec - configuration file (arguments, ip=, port=, rpath). Name based on argv[0]  (/etc/argv[0].cfg)
 * 0.0.3 2009 Dec - put command for all servers
 * 0.0.4 2010 Jan - multiply put for trunc, write
 * 0.0.5 2010 Jun - correct readdir with /
 */

/*
 * I read (and borrowed) a lot of other FUSE code to write this.
 * Similarities possibly exist- Wholesale reuse as well of other GPL code. *
 * Consider this code GPLv2.
 */
#define FUSE_USE_VERSION 26

//#define DEBUG_GET_LIST_S
//#define DEBUG_GET_LIST
#define DEBUG_SYSLOG

#include <sys/statvfs.h>
#include <strings.h>
#include <assert.h>
#include <sys/xattr.h>
#include <dirent.h>
#include <fuse.h>
#include "common-client.h"


// int Clifd;

/*
 *   
 * Callbacks for FUSE 
 * 
 */
 
static int callback_getattr(const char *path, struct stat *st_data)
{
    struct comm *res;
    unsigned int l = 0;
    char buf[BUF];
    uint16_t a;
	int16_t ret;
    struct timespec czas;
	ret = -ENOENT;
    l = strlen(path);
    
    memset(buf, 0, BUF);
    memset(st_data, 0, sizeof (struct stat));
    if (rpath[0] == '\0') {
        sprintf(buf, "<rinfo/r><n%s/n>", path);
    } else {
        if ((path[0] == 47) && (strlen(path) == 1))
            sprintf(buf, "<rinfo/r><n%s/n>", rpath);
        else
            sprintf(buf, "<rinfo/r><n%s%s/n>", rpath, path);
    }

    for(a = 0; a < MAX_IP;a++) {
         #ifdef DEBUG_SYSLOG
        syslog (priority,"get attr dla %s  l %d dla %s\n", buf, l, ip[a]);
        #endif
        if (ip[a])
            res = get_list(buf, 0, 0, Clifd, ip[a]);
     
        if (res) break;
    }   
    
    /*
     * sprawdzenie czy jest
     */
     if (res) {
     #ifdef DEBUG_SYSLOG
    syslog (priority,"res %s\n", res->command);
    #endif
	if (strfind(res->command, "- OK") > 0) {
         #ifdef DEBUG_SYSLOG
        syslog (priority,"dla %s size %d czas %d.%d mode %d owner %d group %d\n",res->command, res->stop, res->t_sec, res->t_msec, res->mode, res->owner, res->group);
        #endif
        czas.tv_sec = res->t_sec;
        czas.tv_nsec = res->t_msec;
        st_data->st_size = res->stop;
        st_data->st_uid = res->owner;
        st_data->st_gid = res->group;
        st_data->st_atim = czas;
        st_data->st_ctim = czas;
        st_data->st_mtim = czas;
        st_data->st_blksize = 0;
        st_data->st_blocks = 0;
        st_data->st_mode = res->mode;       
		ret = 0;
	}
        free(res);    

    }
   return ret;
}

static int callback_readlink(const char *path, char *buf, size_t size)
{
   	int res = 0;
        (void)size;
 #ifdef DEBUG_SYSLOG
	 syslog (priority,"readlink dla %s\n", path);
          #endif
 
    if(res == -1) {
        return -errno;
    }
    buf[res] = '\0';
    return 0;
}

static int callback_readdir(const char *path, void *buf, fuse_fill_dir_t filler,off_t offset, struct fuse_file_info *fi)
{

    (void) offset;
    (void) fi;
    uint16_t a, b, c;
    char *s;
    char name[NAME_SIZE + 20];

    struct comm *res;
     
    if (rpath[0] != '\0') {
        sprintf(name, "<rlist/r><n%s%s", rpath,path);
     } else {
        sprintf(name, "<rlist/r><n%s",path);
     }
    if (strlen(path) > 1) sprintf(name, "%s/", name);

    sprintf (name, "%s/n>", name);
  
    for(a = 0; a < MAX_IP;a++) {
         #ifdef DEBUG_SYSLOG
        syslog (priority,"readdir: rpath >%s< katalog >%s< od %s full name %s\n", rpath,path, ip[a], name);
        #endif
        if (ip[a])
            res = get_list(name, 0, 0, Clifd, ip[a]);
        
        if (res) break;
    }
    if (!res) return -errno;
    s = res->buf;
    /*
     * a - wskaznik przweszukujacy bufor
     * b - wielkosc pojedynczej linii
     * c - wskaznik na pierwsza litere nazwy
     */
     filler(buf, ".", NULL, 0);           /* Current directory (.)  */
    filler(buf, "..", NULL, 0);          /* Parent directory (..)  */
    #ifdef DEBUG_SYSLOG
    syslog(priority, "list dostalo size %d", res->size);
    #endif
    if ((res->buf)&& (res->size)) {
        for (a = 0, b = 0, c = 0; a < res->size;a++) {
            if (s[a] < 32) {
                char name[NAME_SIZE];
                struct stat st;
                memset(&st, 0, sizeof(st));
                memset(name, 0, NAME_SIZE);
                memcpy(name, res->buf + c,b);
                #ifdef DEBUG_SYSLOG
                syslog(priority, "plik %s", name);
                #endif
                if (filler(buf, name, &st, 0)) break;
                b = 0;
                c = a + 1;                
            } else {
                b++;
            }
        }
        free(res->buf); 
    }
    free(res);

    return 0;
}
static int generic(const char *command, const char *name, const char *rest, char *buf)
{
struct timeval cz;
  uint32_t sec, msec; 
  int16_t ret = -EROFS;
  uint16_t a;
   struct comm *res;
char comm[BUF_HEAD];   

gettimeofday(&cz, NULL);

  sec = cz.tv_sec;
  msec = cz.tv_usec;
if (rpath[0] != '\0') {
        sprintf(comm, "<r%s/r><n%s%s/n><v%d.%d/v>",command, rpath,name, sec, msec);
     } else {
        sprintf(comm, "<r%s/r><n%s/n><v%d.%d/v>", command, name, sec, msec);
     }
if (rest) {
	sprintf(comm, "%s%s", comm, rest);
}
    #ifdef DEBUG_SYSLOG
    syslog (priority,"command %s dla %s dane %s\n",  command, name, comm);
    #endif

  for (a = 0; a < MAX_IP;a++) {
    if (ip[a]) {
	if (buf) {
       res = get_list(comm, buf, strlen(buf), Clifd, ip[a]);

	} else {
        res = get_list(comm, 0, 0, Clifd, ip[a]);
}
        if (res)
            free(res);
            ret = 0;        
    }
}
   return ret;
}
static int callback_mknod(const char *path, mode_t mode, dev_t rdev)
{
  // (void)mode;
  (void)rdev;
  char rest[BUF_HEAD];     
  
   #ifdef DEBUG_SYSLOG
  syslog (priority,"mknod dla %s with mode %d O_RD %d O_WR %d O_RDWR %d O_CREAT %d O_EXCL %d O_TRUNC %d O_APPEND %d\n", path, mode, mode & O_RDONLY, mode & O_WRONLY, mode & O_RDWR, mode & O_CREAT, mode & O_EXCL,mode & O_TRUNC,mode & O_APPEND);
  #endif
 sprintf(rest, "<u%d/u>", mode);
 return generic("put", path, rest,0);
}

static int callback_mkdir(const char *path, mode_t mode)
{
    mode_t mode1 = 0040000 | mode;
   
    char rest[BUF_HEAD];

    
    #ifdef DEBUG_SYSLOG
    syslog (priority,"mkdir dla %s%s with mode %d\n", rpath, path, mode1);
    #endif
   
    sprintf(rest, "<u%d/u>", mode1);
    return generic("put", path, rest, 0);
   
}

static int callback_unlink(const char *path)
{ 	
    return generic("delete", path, 0, 0);
}

static int callback_rmdir(const char *path)
{

    #ifdef DEBUG_SYSLOG
    syslog (priority,"rmdir dla %s\n",  path);
    #endif 

    return generic("delete", path, 0, 0);
  
}

static int callback_symlink(const char *from, const char *to)
{
  (void)from;
  (void)to;
  syslog (priority,"symlink from %s to %s\n", from, to);
  return -EROFS;	
}

static int callback_rename(const char *from, const char *to)
{  
  
  
    if (rpath[0] != '\0') {
        char z[NAME_SIZE];
  //      char y[NAME_SIZE];

        memset(z, 0,NAME_SIZE);
   //     memset(y, 0, NAME_SIZE);
        
        sprintf(z, "%s%s", rpath, from);
   //     sprintf(y, "%s%s", rpath, to);
        return generic("rename", to, 0,z);
    }  

  return generic("rename", to, 0, (char *)from);
}

static int callback_link(const char *from, const char *to)
{  
   char z[NAME_SIZE];
  
  #ifdef DEBUG_SYSLOG
  syslog (priority,"link rpath %s from %s to %s\n", rpath,from, to);
  #endif
  if (rpath[0] != '\0') {        
        sprintf(z, "%s%s", rpath, from);
     } else {
        sprintf(z, "%s", from);        
     } 

    return generic("link", to, 0, z);

}

static int callback_chmod(const char *path, mode_t mode)
{
    char rest[BUF_HEAD];
    sprintf(rest, "<u%d/u>", mode);
    return generic("put", path, rest, 0);
  
}

static int callback_chown(const char *path, uid_t uid, gid_t gid)
{
    char rest[BUF_HEAD];
    sprintf(rest, "<o%d %d/o>", uid, gid);
    return generic("mode", path, rest, 0);
}

static int callback_truncate(const char *path, off_t size)
{
    return generic("trunc", path, 0, 0);
}

static int callback_utime(const char *path, struct utimbuf *buf)
{
	(void)path;
  	(void)buf;

         syslog (priority,"utime dla %s\n", path);

  	return 0;
//	return generic("put", path, ?, 0);

        // return -EROFS;
}

static int callback_open(const char *path, struct fuse_file_info *finfo)
{
	//int res;
	
	/* We allow opens, unless they're tring to write, sneaky
	 * people.
	 */
	int flags = finfo->flags;
        // int mode = finfo->
       //  #ifdef DEBUG_SYSLOG
	syslog (priority,"open dla %s with flag %d O_RD %d O_WR %d O_RDWR %d O_CREAT %d O_EXCL %d O_TRUNC %d O_APPEND %d\n", path, flags, flags & O_RDONLY, flags & O_WRONLY, flags & O_RDWR, flags & O_CREAT, flags & O_EXCL,flags & O_TRUNC,flags & O_APPEND);
       // #endif
        /*
         * checking that file can be read or write
         */
//	if ((flags & O_WRONLY) || (flags & O_RDWR) || (flags & O_CREAT) || (flags & O_EXCL) || (flags & O_TRUNC) || (flags & O_APPEND)) {
//      return -EROFS;
//  	}
  	
  /*	path=translate_path(path);
  
    res = open(path, flags);
 
    free(path);
    if(res == -1) {
        return -errno;
    }
    close(res);*/
    return 0;
}

static int callback_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *finfo)
{    
    int ret;
    (void)finfo;

    char comm[BUF_HEAD];
    memset(comm, 0, BUF_HEAD);
    uint32_t a;
    #ifdef __x86_64
    if (rpath[0] == '\0') {
        sprintf(comm, "<rget/r><n%s/n><s%ld/s><e%ld/e>",path, offset, offset + size);
    } else {
        if ((path[0] == 47) && (strlen(path) == 1))
               sprintf(comm, "<rget/r><n%s/n><s%ld/s><e%ld/e>",rpath, offset, offset + size);
        else
            sprintf(comm, "<rget/r><n%s%s/n><s%ld/s><e%ld/e>",rpath, path, offset, offset + size);
    }
    #else
    if (rpath[0] == '\0') {
        sprintf(comm, "<rget/r><n%s/n><s%d/s><e%d/e>",path, (uint32_t)offset, (uint32_t)offset + (uint32_t)size);
    } else {
        if ((path[0] == 47) && (strlen(path) == 1))
               sprintf(comm, "<rget/r><n%s/n><s%d/s><e%d/e>",rpath, (uint32_t)offset, (uint32_t)offset + (uint32_t)size);
        else
            sprintf(comm, "<rget/r><n%s%s/n><s%d/s><e%d/e>",rpath, path, (uint32_t)offset, (uint32_t)offset + (uint32_t)size);
    }
    #endif
      #ifdef DEBUG_SYSLOG
     syslog (priority,"%s", comm);
     #endif
    
    for(a = 0; a < MAX_IP;a++) {
        struct comm *res;

        if (ip[a])
            res = get_list(comm, 0, 0, Clifd, ip[a]);
        
        if (res) {
            ret = res->size;
            #ifdef DEBUG_SYSLOG
            syslog (priority,"read size %d\n", ret);
            #endif
            buf = memcpy(buf, res->buf, ret);
            #ifdef DEBUG_SYSLOG
            syslog (priority,"free #1 %p %p\n", res, res->buf);
            #endif
            if ((ret)&& (res->buf)) free(res->buf);
            free(res);
            return ret;
        }
    }
   
   return -errno;
}

static int callback_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *finfo)
{
    (void)finfo;
    uint16_t ret = -1;
    struct timeval cz;
    uint32_t sec, msec;
    uint32_t a;
    char comm[NAME_SIZE];
    memset(comm, 0, NAME_SIZE);

    gettimeofday(&cz, NULL);
    sec = cz.tv_sec;
    msec = cz.tv_usec;    

    if (rpath[0] != '\0') {
        sprintf(comm, "%s%s",rpath, path);
    } else {
        sprintf(comm, "%s", path);

     }
    #ifdef DEBUG_SYSLOG
            //syslog (priority,"write start %s size %d\n", comm, size);
    #endif
    for(a = 0; a < MAX_IP;a++) {
        if (ip[a]) {
            int ret1;
            ret1 = multiply_put(comm, buf, size, offset, Clifd, ip[a], sec, msec);
            if (ret1 > -1) ret = ret1;
        }
       
    }
    #ifdef DEBUG_SYSLOG
            syslog (priority,"write end %d\n", ret);
    #endif
    return ret;
  
}

static int callback_statfs(const char *path, struct statvfs *st_buf)
{
  int res = 0;
  (void) st_buf;
  syslog (priority,"statfs dla %s\n", path);
 
  //res = statvfs(path, st_buf);
  //free(path);
  if (res == -1) {
    return -errno;
  }
  return 0;
}

static int callback_release(const char *path, struct fuse_file_info *finfo)
{
  (void) path;
  (void) finfo;
  #ifdef DEBUG
   syslog (priority,"release dla %s\n", path);
   #endif
  return 0;
}

static int callback_fsync(const char *path, int crap, struct fuse_file_info *finfo)
{
  (void) path;
  (void) crap;
  (void) finfo;
   syslog (priority,"fsync dla %s\n", path);
  return 0;
}
static int callback_flush(const char *path, struct fuse_file_info *finfo)
{
  (void) path;
 
  (void) finfo;
  #ifdef DEBUG
   syslog (priority,"flush dla %s\n", path);
   #endif
  return 0;
}
static int callback_access(const char *path, int mode)
{
	int res;
  //	path=translate_path(path);
  	 syslog (priority,"access dla %s%s mode %d\n", rpath, path, mode);
  	/* Don't pretend that we allow writing
  	 * Chris AtLee <chris@atlee.ca>
  	 */
    // if (mode & W_OK)
//        return -EROFS;
        
//  	res = access(path, mode);
//	free(path);
  //	if (res == -1) {
    //	return -errno;
  //	}
         /*
          * WARNING: we agree for everything
          */
         res = 0;
  	return res;
}

/*
 * Set the value of an extended attribute
 */
static int callback_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
	(void)path;
	(void)name;
	(void)value;
	(void)size;
	(void)flags;
         syslog (priority,"setxattr dla %s\n", path);
         return 0;
	//return -EROFS;
}

/*
 * Get the value of an extended attribute.
 */
static int callback_getxattr(const char *path, const char *name, char *value, size_t size)
{
    (void) path;
    (void) name;
    (void) value;
    (void) size;

     #ifdef DEBUG_SYSLOG
      syslog (priority,"getxattr dla %s size %d\n", path,(uint32_t) size);
      #endif
 
      /*
       * we don't support GETXATTR now
       */
    return -ENOTSUP;
}

/*
 * List the supported extended attributes.
 */
static int callback_listxattr(const char *path, char *list, size_t size)
{
	int res = 0;
	(void) list;
        (void) size;
//	path=translate_path(path);
//	res = llistxattr(path, list, size);
         syslog (priority,"listxattr dla %s\n", path);
  // 	free(path);
           
    if(res == -1) {
        return -errno;
    }
    return res;

}

/*
 * Remove an extended attribute.
 */
static int callback_removexattr(const char *path, const char *name)
{
	(void)path;
  	(void)name;
          syslog (priority,"removexattr dla %s\n", path);
  	return -EROFS;

}

struct fuse_operations callback_oper = {
    .getattr	= callback_getattr,
    .readlink	= callback_readlink,
    .readdir	= callback_readdir,
    .mknod		= callback_mknod,
    .mkdir		= callback_mkdir,
    .symlink	= callback_symlink,
    .unlink		= callback_unlink,
    .rmdir		= callback_rmdir,
    .rename		= callback_rename,
    .link		= callback_link,
    .chmod		= callback_chmod,
    .chown		= callback_chown,
    .truncate	= callback_truncate,
    .utime		= callback_utime,
    .open		= callback_open,
    .read		= callback_read,
    .write		= callback_write,
    .statfs		= callback_statfs,
    .release	= callback_release,
    .fsync		= callback_fsync,
    .access		= callback_access,

    .flush              = callback_flush,
    /* Extended attributes support for userland interaction */
    .setxattr	= callback_setxattr,
    .getxattr	= callback_getxattr,
    .listxattr	= callback_listxattr,
    .removexattr= callback_removexattr
};
enum {
    KEY_HELP,
    KEY_VERSION,
};

int main(int argc, char *argv[])
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    char cname[50];
    uint16_t s = 0, a = 0;
    
    srand(time(0));
    openlog(argv[0], 0, LOG_USER);


     for(a = 0;a < strlen(argv[0]); a++)
        if (argv[0][a] == '/') s = a;

     sprintf(cname,"/etc%s.cfg",&argv[0][s]);
     
     if (!read_file (cname, ip, 0)) blad ("blad pobrania serwerow\n");

     if (!start_port) syslog (priority, "FUSE: there isn't port= variable in configuration file");

     Clifd = bind_port();
     

     if (rpath[0] != '\0') {
         syslog(priority, "relative path is >%s<\n", rpath);

     } else {
         syslog(priority, "relative path not set\n");
     }
    #if FUSE_VERSION >= 26
        fuse_main(args.argc, args.argv, &callback_oper, NULL);
    #else
        fuse_main(args.argc, args.argv, &callback_oper);
    #endif

    return 0;
}

