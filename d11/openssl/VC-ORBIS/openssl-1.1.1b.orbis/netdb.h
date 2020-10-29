/* netdb.h */

/* Provide Orbis UNIX compatibility */


#ifndef  _INC_NETDB
#define  _INC_NETDB

#include <fcntl.h>
#include <net.h>

#include <netinet/in.h>

#define h_errno 0

struct  hostent {
	char *  h_name;
	char ** h_aliases;
	int     h_addrtype;
	int     h_length;
	char ** h_addr_list;
};

struct in6_addr {
	unsigned char   s6_addr[16];   /* IPv6 address */
};

struct sockaddr_in6 {
	__sa_family_t   sin6_family;   /* AF_INET6 */
	in_port_t       sin6_port;     /* port number */
	uint32_t        sin6_flowinfo; /* IPv6 flow information */
	struct in6_addr sin6_addr;     /* IPv6 address */
	uint32_t        sin6_scope_id; /* Scope ID (new in 2.4) */
};

struct sockaddr_un
{
	__sa_family_t	sun_family;      /* AF_UNIX */
	char			sun_path[108];   /* pathname */
};

struct servent {
	char *  s_name;
	char ** s_aliases;
	int    s_port;
	char *  s_proto;
};

#define getenv(name)				NULL
#define gethostbyname(name)			NULL
#define getservbyname(name, proto)	NULL
#define inet_ntoa(inAddress)		NULL // TODO: { char destination[SCE_NET_INET_ADDRSTRLEN]; return sceNetInetNtop(SCE_NET_AF_INET, (const void*)&inAddress, destination, SCE_NET_INET_ADDRSTRLEN); }
#define ioctl						fcntl
#define issetugid()					0

#endif /* _INC_NETDB */
