#pragma warning (disable : 4996)
#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <chrono>

//ICMP MESSAGES TYPES
#define ICMP_ECHOREPLY      0
#define ICMP_DESTUNREACH    3
#define ICMP_SRCQUENCH      4
#define ICMP_REDIRECT       5
#define ICMP_ECHOREQUEST    8
#define ICMP_TIMEOUT       11
#define ICMP_PARMERR       12

#define MAX_HOPS           30

#define ICMP_MIN            8  
#define DEF_PACKET_SIZE	   32
#define MAX_PACKET       1024

//заголовок сетевого уровня (IP)
typedef struct iphdr
{
	unsigned int   h_len : 4;        // Length of the header
	unsigned int   version : 4;      // Version of IP
	unsigned char  tos;            // Type of service
	unsigned short total_len;      // Total length of the packet
	unsigned short ident;          // Unique identifier
	unsigned short frag_and_flags; // Flags
	unsigned char  ttl;            // Time to live
	unsigned char  proto;          // Protocol (TCP, UDP etc)
	unsigned short checksum;       // IP checksum
	unsigned int   sourceIP;       // Source IP
	unsigned int   destIP;         // Destination IP
} IpHeader;

//заголовок ICMP
typedef struct icmphdr
{
	byte   i_type;              // ICMP message type
	byte   i_code;              // Sub code
	unsigned short i_cksum;		//checksum
	unsigned short i_id;        // Unique id
	unsigned short i_seq;       // Sequence number
	unsigned long timestamp;
} IcmpHeader;

int set_ttl(SOCKET s, int nTimeToLive)
{
	int isInvalidSock = setsockopt(s, IPPROTO_IP, IP_TTL, (char*)&nTimeToLive, sizeof(int));
	if (isInvalidSock == SOCKET_ERROR)
	{
		std::cout << "setsockopt(IP_TTL) failed : " << WSAGetLastError();
		return 0;
	}
	return 1;
}

auto begin = std::chrono::steady_clock::now();
auto end = std::chrono::steady_clock::now();
/*декодируем IP пакет чтобы определить данные в ICMP пакете*/
int decode_resp(char *buf, int bytes, SOCKADDR_IN *from, int ttl)
{
	IpHeader *iphdr = NULL;
	IcmpHeader *icmphdr = NULL;
	unsigned short iphdrlen;
	struct hostent *lpHostent = NULL;
	struct in_addr inaddr = from->sin_addr;

	iphdr = (IpHeader *)buf;
	iphdrlen = iphdr->h_len * 4;
	if (bytes < iphdrlen + ICMP_MIN)
		std::cout << "Too few bytes from : " << inet_ntoa(from->sin_addr);

	icmphdr = (IcmpHeader*)(buf + iphdrlen);

	end = std::chrono::steady_clock::now();
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);
	switch (icmphdr->i_type)
	{
	case ICMP_ECHOREPLY: //если ответил конечный роутер
		lpHostent = gethostbyaddr((const char *)&from->sin_addr, AF_INET, sizeof(struct in_addr));
		if (WSAGetLastError() != 0) {
			std::cout << ttl << '\t' << ms.count() << "ms \t" << inet_ntoa(inaddr) << '\n';
			WSACleanup();
		}
		else
			std::cout << ttl << '\t' << ms.count() << "ms \t" << lpHostent->h_name << '[' << inet_ntoa(inaddr) << ']' << '\n';
		return 1;
		break;
	case ICMP_TIMEOUT:  //промежуточный
		lpHostent = gethostbyaddr((const char *)&from->sin_addr, AF_INET, sizeof(struct in_addr));
		if (WSAGetLastError() != 0) {
			std::cout << ttl << '\t' << ms.count() << "ms \t" << inet_ntoa(inaddr) << '\n';
		}
		else
			std::cout << ttl << '\t' << ms.count() << "ms \t" << lpHostent->h_name << '[' << inet_ntoa(inaddr) << ']' << '\n';
		return 0;
		break;
	case ICMP_DESTUNREACH:  //если маршрутизатор недостижим
		std::cout << "Host is unreachable " << ttl << "\t" << inet_ntoa(inaddr);
		return 1;
		break;
	}
	return 0;
}

unsigned short checksum(unsigned short *buffer, int size)
{
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}
	if (size)
		cksum += *(unsigned short*)buffer;
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (unsigned short)(~cksum);
}

void fill_icmp_data(char * icmp_data, int datasize)
{
	IcmpHeader *icmp_hdr = (IcmpHeader*)icmp_data;
	icmp_hdr->i_type = ICMP_ECHOREQUEST;
	icmp_hdr->i_code = 0;
	icmp_hdr->i_cksum = 0;
	icmp_hdr->i_seq = 0;
	char *datapart = icmp_data + sizeof(IcmpHeader);
	memset(datapart, 'A', datasize - sizeof(IcmpHeader));
}

int main(int argc, char **argv)
{
	WSADATA wsd;
	//инициализируем библиотеку
	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
	{
		std::cout << "WSAStartup() failed:" << GetLastError();
		return -1;
	}
	//создаем сырой сокет
	SOCKET sockRaw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockRaw == INVALID_SOCKET)
	{
		std::cout << "WSASocket() failed : " << WSAGetLastError();
		ExitProcess(-1);
	}
	//устанавливаем тайм-аут для входящих запросов
	int timeout = 1000;
	int ret = setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
	if (ret == SOCKET_ERROR)
	{
		std::cout << "setsockopt(SO_RCVTIMEO) failed: " << WSAGetLastError();
		return -1;
	}
	//Проверяем существует ли указанный хост/адрес
	SOCKADDR_IN Destinition, from;
	ZeroMemory(&Destinition, sizeof(Destinition));
	Destinition.sin_family = AF_INET;
	if ((Destinition.sin_addr.s_addr = inet_addr(argv[1])) == INADDR_NONE)
	{
		HOSTENT *isHostExists = gethostbyname(argv[1]);
		if (isHostExists)
			memcpy(&(Destinition.sin_addr), isHostExists->h_addr, isHostExists->h_length);
		else
		{
			std::cout << "Unable to resolve " << argv[1];
			ExitProcess(-1);
		}
	}
	/*устанавливаем размер пакета данных (32 байта)
	и выделяем память под отправляющий и принимающий буфер для ICMP пакетов*/
	int datasize = DEF_PACKET_SIZE;
	char *icmp_data = (char*)malloc(MAX_PACKET);
	char *recvbuf = (char*)malloc(MAX_PACKET);
	if ((!icmp_data) || (!recvbuf))
	{
		std::cout << "malloc() failed : " << GetLastError();
		return -1;
	}  
	//создаем и заполняем заголовок ICMP
	memset(icmp_data, 0, MAX_PACKET);
	fill_icmp_data(icmp_data, datasize);

	std::cout << "Tracing route to " << argv[1] << " over a maximum of " << MAX_HOPS << " hops : \n";
	int done = 0;
	unsigned short seq_no = 0;
	for (int ttl = 1; ((ttl <= MAX_HOPS) && (!done)); ttl++)
	{	
		begin = std::chrono::steady_clock::now();
		//устанавливаем ttl на сокет
		set_ttl(sockRaw, ttl);

		((IcmpHeader*)icmp_data)->i_cksum = 0;
		((IcmpHeader*)icmp_data)->timestamp = GetTickCount();
		((IcmpHeader*)icmp_data)->i_seq = seq_no++;
		//считаем контрольную сумму для заголовка ICMP 
		((IcmpHeader*)icmp_data)->i_cksum = checksum((unsigned short*)icmp_data, datasize);

		//отправляем ICMP пакет до конечного маршрутизатора
		int bwrote = sendto(sockRaw, icmp_data, datasize, 0, (SOCKADDR *)&Destinition, sizeof(Destinition));
		if (bwrote == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAETIMEDOUT)
			{
				std::cout << "Send request timed out. \n" << ttl;
				continue;
			}
			std::cout << "sendto() failed: \n" << WSAGetLastError();
			return -1;
		}
		//принимаем отправленный от промежуточного или конечного маршрутизатора пакет
		int fromlen = sizeof(SOCKADDR_IN);
		ret = recvfrom(sockRaw, recvbuf, MAX_PACKET, 0, (struct sockaddr*)&from, &fromlen);
		if (ret == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAETIMEDOUT)
			{
				std::cout << ttl << "\t *" << '\t' << "Receive Request timed out.\n";
				continue;
			}
			std::cout << "recvfrom() failed: \n" << WSAGetLastError();
			return -1;
		}
		//определяем, дошли ли мы до конечного маршрутизатора
		done = decode_resp(recvbuf, ret, &from, ttl);	
		Sleep(100);
	}
	HeapFree(GetProcessHeap(), 0, recvbuf);
	HeapFree(GetProcessHeap(), 0, icmp_data);
	return 0;
}