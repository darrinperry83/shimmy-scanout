#define main relay_program_main
#include "relay.c"
#undef main
#include <assert.h>

int rd_verify_peer_audit(int fd,const char *path){(void)fd;(void)path;return 1;}
static void put(unsigned char *b,size_t at,uint32_t value){memcpy(b+at,&value,4);}
static int send_wire(struct parse *p,int target,const unsigned char *bytes,
                     size_t size,int right){
    struct queued_message q={0};memcpy(q.data,bytes,size);q.len=size;
    if(right>=0){q.rights[0]=dup(right);assert(q.rights[0]>=0);q.nr=1;}
    size_t sent=0,fds=0;return flush_queue(target,&q,p,0,&sent,&fds);
}
static int check_wire(struct parse *p,const unsigned char *bytes,size_t size,
                      int right){
    struct queued_message q={0};memcpy(q.data,bytes,size);q.len=size;
    if(right>=0){q.rights[0]=right;q.nr=1;}
    return prevalidate_client(&q,p);
}
int main(void){
    struct parse *p=calloc(1,sizeof *p);assert(p);
    p->strict_capability=1;p->host_connection=77;p->peer_pid=123;
    p->supervisor_fd=p->event_fd=p->owned_event_fd=-1;
    int witness[2],backend[2];assert(pipe(witness)==0);
    assert(socketpair(AF_UNIX,SOCK_STREAM,0,backend)==0);
    p->dmabuf_event_fd=witness[1];rd_obj_init(p);
    struct rd_object *registry=rd_new(p,2);registry->type=RD_REGISTRY;
    const char name[]="zwp_linux_dmabuf_v1";
    unsigned char global[40]={0};put(global,0,2);put(global,4,40u<<16);
    put(global,8,91);put(global,12,sizeof name);memcpy(global+16,name,sizeof name);
    put(global,36,3);assert(publish_parse(p,global,sizeof global,1)==0);
    unsigned char bind[44]={0};put(bind,0,2);put(bind,4,44u<<16);
    put(bind,8,91);put(bind,12,sizeof name);memcpy(bind+16,name,sizeof name);
    put(bind,36,3);put(bind,40,10);
    assert(send_wire(p,backend[0],bind,sizeof bind,-1)==1);
    assert(rd_view(p,10)->type==RD_DMABUF_MANAGER);
    unsigned char modifier[20]={0};put(modifier,0,10);put(modifier,4,20u<<16|1);
    put(modifier,8,RD_DMABUF_ARGB8888);
    struct queued_message server_event={0};
    memcpy(server_event.data,modifier,sizeof modifier);server_event.len=sizeof modifier;
    assert(prevalidate_server(&server_event,p)==1);
    assert(publish_parse(p,modifier,sizeof modifier,1)==0);
    unsigned char make[12]={0};put(make,0,10);put(make,4,12u<<16|1);
    put(make,8,11);assert(send_wire(p,backend[0],make,sizeof make,-1)==1);
    assert(rd_view(p,11)->type==RD_DMABUF_PARAMS);
    char path[]="/tmp/rd-dmabuf-relay-XXXXXX";
    int fd=mkstemp(path);assert(fd>=0);unlink(path);
    assert(ftruncate(fd,2048)==0);
    struct stat stat0;assert(fstat(fd,&stat0)==0);
    int scm[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,scm)==0);
    unsigned char byte=1,control[CMSG_SPACE(sizeof(int))]={0};
    struct iovec io={&byte,1};struct msghdr msg={0};
    msg.msg_iov=&io;msg.msg_iovlen=1;msg.msg_control=control;
    msg.msg_controllen=sizeof control;
    struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c->cmsg_level=SOL_SOCKET;
    c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c),&fd,sizeof fd);
    assert(sendmsg(scm[0],&msg,0)==1);
    struct queued_message received={0};assert(enqueue(scm[1],&received)==1);
    assert(received.nr==1&&(fcntl(received.rights[0],F_GETFD)&FD_CLOEXEC));
    discard_queue(&received);close(scm[0]);close(scm[1]);
    unsigned char add[28]={0};put(add,0,11);put(add,4,28u<<16|1);
    put(add,16,128); /* plane zero, offset zero, padded IOSurface stride */
    assert(check_wire(p,add,sizeof add,-1)==-1); /* missing FD */
    put(add,24,1);assert(check_wire(p,add,sizeof add,fd)==-1);
    put(add,24,0);
    assert(send_wire(p,backend[0],add,sizeof add,fd)==1);
    assert(rd_view(p,11)->dmabuf_dev==(uint64_t)stat0.st_dev);
    assert(rd_view(p,11)->dmabuf_ino==(uint64_t)stat0.st_ino);
    assert(check_wire(p,add,sizeof add,fd)==-1); /* duplicate plane */
    unsigned char create[28]={0};put(create,0,11);put(create,4,28u<<16|3);
    put(create,8,12);put(create,12,16);put(create,16,16);
    put(create,20,RD_DMABUF_ARGB8888);
    assert(check_wire(p,create,sizeof create,-1)==1);
    struct pollfd early={witness[0],POLLIN,0};assert(poll(&early,1,0)==0);
    assert(send_wire(p,backend[0],create,sizeof create,-1)==1);
    struct rd_dmabuf_wire_event e={0};assert(read(witness[0],&e,sizeof e)==sizeof e);
    assert(e.magic==RD_DMABUF_WIRE_CREATE&&e.connection==77&&
           e.params_id==11&&e.buffer_id==12&&e.width==16&&e.height==16&&
           e.stride==128&&e.format==RD_DMABUF_ARGB8888&&
           e.fd_dev==(uint64_t)stat0.st_dev&&e.fd_ino==(uint64_t)stat0.st_ino);
    assert(check_wire(p,create,sizeof create,-1)==-1); /* one-shot params */
    unsigned char drop[8]={0};put(drop,0,12);put(drop,4,8u<<16);
    assert(send_wire(p,backend[0],drop,sizeof drop,-1)==1);
    assert(read(witness[0],&e,sizeof e)==sizeof e&&
           e.magic==RD_DMABUF_WIRE_DESTROY&&e.buffer_id==12&&
           e.fd_ino==(uint64_t)stat0.st_ino);
    close(fd);close(witness[0]);close(witness[1]);
    close(backend[0]);close(backend[1]);free(p);
    puts("DMABUF_RELAY_PASS standard_v3_fd_witness_after_forward exact_geometry duplicate_denial destroy");
}
