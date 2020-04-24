/*
 * Author: Akash Pramodkumar Pateria
 * email: apateri@ncsu.edu
 */

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/time.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>

#include <iostream>
#include <limits>
#include <chrono>
#include <thread>
#include <boost/program_options.hpp>

#define	MAXPACKETLEN 	4096
#define TIMEOUT 		10
#define TTL				54

using namespace std;

int skt, ttl = TTL;
struct sockaddr_in to, from;
unsigned char packet[MAXPACKETLEN];
char hnamebuf[MAXHOSTNAMELEN];
string hostname;
struct hostent *hp;
struct timezone tz;
struct sigaction action, oldaction;
int id, datalen = 56;
int npackets = numeric_limits<int>::max(), preload = 0, ntransmitted = 0, nreceived = 0;
int interval = 1, tmin = numeric_limits<int>::max(), tmax = 0, tsum = 0, timeout = TIMEOUT;

void show_usage();
int set_options(int, char**);
void ping();
void unpack();
uint16_t in_cksum(uint16_t*, unsigned int);
void show_stats(int);


int main(int argc, char *argv[])
{
	if (set_options(argc, argv))
		exit(1);

	if ((skt = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
	{
		cerr << "ping: [ICMP] unknown protocol or Permission denied, try again with sudo\n";
		return -1;
	}
	setsockopt(skt, IPPROTO_IP, IP_TTL, (char *)&ttl, sizeof(ttl));

	cout << "PING " << hostname << " " << datalen << " data bytes\n";
    signal(SIGINT, show_stats);

	for (int p = 0; p < preload; p++)
		ping();

	while(npackets--)
	{
		ping();
		unpack();
		chrono::seconds dura(interval);
		this_thread::sleep_for(dura);
	}
	show_stats(1);
	return 0;
}

void show_usage()
{
	cerr << "Usage: ping [-cilstw] [-c count] [-i interval] [-l preload] [-s packetsize] [-t ttl]" <<
				" [-w timeout] destination\n";
}

int set_options(int argc, char **argv)
{
	if (argc < 2) {
        show_usage();
        return 1;
    }

    std::vector<std::string> args(argv, argv + argc);
	int len = args.size(), i = 1;
	for (; i < args.size() - 1; i++)
	{
		if (args[i] == "-c")
			npackets = stoi(args[++i]);
		else if (args[i] == "-i")
			interval = stoi(args[++i]);
		else if (args[i] == "-l")
			preload = stoi(args[++i]);
		else if (args[i] == "-t")
			ttl = stoi(args[++i]);
		else if (args[i] == "-w")
			timeout = stoi(args[++i]);
		else if (args[i] == "-s") {
			datalen = stoi(args[++i]);
			if (datalen > MAXPACKETLEN) {
				cerr << "ping: Packet size too large\n";
				return 1;
			}
        }
		else
		{
			show_usage();
        	return 1;
		}

	}
	if(len - i != 1)  {
		show_usage();
		return 1;
	}

	bzero((char *)&to, sizeof(struct sockaddr_in));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = inet_addr(argv[args.size() - 1]);
	if(to.sin_addr.s_addr != (unsigned)-1)
	{
		strcpy(hnamebuf, argv[0]);
		hostname = hnamebuf;
	}
	else
	{
		hp = gethostbyname(argv[args.size() - 1]);
		if (hp) {
			to.sin_family = hp->h_addrtype;
			bcopy(hp->h_addr, (caddr_t)&to.sin_addr, hp->h_length);
			hostname = hp->h_name;
		} else {
			cerr << "ping: " << argv[0] << ": Name or service not known\n";
			return 1;
		}
	}
	id = getpid() & 0xFFFF;
	return 0;
}

void ping()
{
    int i, cc = datalen+8;

	unsigned char outpack[MAXPACKETLEN];
	struct ip *ip = (struct ip *)((char*)packet);
	struct icmp *icmp_ = (struct icmp *)outpack;
	struct timeval *tp = (struct timeval *) &outpack[8];

	icmp_->icmp_type = ICMP_ECHO;
	icmp_->icmp_code = 0;
	icmp_->icmp_cksum = 0;
	icmp_->icmp_seq = ntransmitted++;
	icmp_->icmp_id = id;

	gettimeofday(tp, &tz);
	icmp_->icmp_cksum = in_cksum((unsigned short *)icmp_, cc);

	i = sendto(skt, (char *)outpack, cc, 0, (struct sockaddr*)&to, (socklen_t)sizeof(struct sockaddr_in));
	if (i < 0 || i != cc)
	{
		if (i < 0)
			cout << "ping: Error occured in sendto call\n";
		cout << "ping: Sent to " << hostname << " " <<  cc << " characters and received " << i << endl;
	}
}


void unpack()
{
	int cc, fromlen, hlen, triptime;
	struct ip *ip;
	struct timeval timeout_, *ep;
	fd_set rfds;

	FD_ZERO(&rfds);
	FD_SET(skt, &rfds);
	timeout_.tv_sec = timeout;
	timeout_.tv_usec = 0;

	for(;;)
	{
		cc = select(32, &rfds, 0, 0, &timeout_);
		if (cc == -1)
		{
			cerr << "ping: Error occured in select call\n";
			return;
		}
		else if (cc)
		{
			struct icmp *icp;
			struct timeval tv;
			fromlen = sizeof(sockaddr_in);
			if ((cc = recvfrom(skt, packet, sizeof (packet), 0, (struct sockaddr *)&from, (socklen_t*)&fromlen)) < 0)
			{
				cerr << "ping: Error occured in recvfrom call\n";
				return;
			}
			gettimeofday(&tv, &tz);

			ip = (struct ip *)((char*)packet);
			hlen = ip->ip_hl << 2;
			if (cc < (hlen + ICMP_MINLEN))
			{
				cerr << "ping: Packet too short (" << cc  << " bytes) from " << hostname << endl;;
				return;
			}

			cc -= hlen;
			icp = (struct icmp *)(packet + hlen);
			if (icp->icmp_type != ICMP_ECHOREPLY)  {
				cout << cc << " bytes from " << inet_ntoa(from.sin_addr) << " icmp_type=" << icp->icmp_type << "icmp_code=" <<  icp->icmp_code << endl;
				return;
			}
			if (icp->icmp_id != id)
				return;

			ep = (struct timeval *)&icp->icmp_data[0];
			if( (tv.tv_usec -= ep->tv_usec) < 0 )   {
				tv.tv_sec--;
				tv.tv_usec += 1000000;
			}
			tv.tv_sec -= ep->tv_sec;
			triptime = tv.tv_sec*1000+(tv.tv_usec/1000);
			tsum += triptime;
			if( triptime < tmin )
				tmin = triptime;
			if( triptime > tmax )
				tmax = triptime;

			cout << cc << " bytes from " << hostname << "(" << inet_ntoa(from.sin_addr) << "): icmp_seq=" << icp->icmp_seq << " ttl=" << ttl << " time=" << triptime << "ms" << endl;
			nreceived++;
			break;
		}
		else
		{
			cout << cc << " bytes from " << hostname << "(" << inet_ntoa(from.sin_addr) << "): " << "Time exceeded: Hop limit\n";
			return;
		}
	}
}

uint16_t in_cksum(unsigned short *addr, unsigned int len)
{
  uint16_t answer = 0;
  uint32_t sum = 0;
  unsigned short *buf = (unsigned short *) addr;

  for (sum = 0; len > 1; len -= 2)
    sum += *buf++;
  if (len == 1)
	sum += *(unsigned char*)buf;

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return answer;
}

void show_stats(int sig_no)
{
	cout << "\n----  " << hostname << " ping statistics ----\n";
	cout << ntransmitted << " packets transmitted, " << nreceived << " packets received, " <<
		(int) (((ntransmitted-nreceived)*100)/ntransmitted) << "% packet loss\n";
	if (nreceived)
	    cout << "rtt min/avg/max = " << tmin  << "/" << tsum / nreceived << "/" << tmax << " ms\n";
	exit(0);
}
