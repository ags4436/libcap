#include<stdio.h>
#include<stdlib.h>
#include<pcap.h> //To invoke the Libpcap Library and use its functions 
#include<errno.h> //For error numbers 
#include<sys/socket.h>
#include<netinet/in.h> // Used for Ipv6 or ipv4 Types 
#include<arpa/inet.h> // arpa is a package, which has basic things like telnet, ip, lookup etc 
#include<time.h>
#include<netinet/if_ether.h>

int main(){
 char *device_name;
 char error[PCAP_ERRBUF_SIZE]; 
 pcap_t* pack_decs;
 const u_char *packet;
 struct pcap_pkthdr header; 
 struct ether_header *eptr; // defined in ethernet.h
 int i;
 u_char *hard_ptr;

 device_name = pcap_lookupdev(error);
 if(device_name==NULL){
  	printf("%s\n",error);
	return -1;  
  }else{
  	printf("Device: %s\n",device_name);
  }
  
  pack_decs = pcap_open_live(device_name, BUFSIZ, 0, 1, error);
  if(pack_decs==NULL){
  	printf("%s\n",error);
	return -1;
  }
 while(1)
 {
  packet = pcap_next(pack_decs, &header);
  printf("\n#\n");
  if(packet==NULL){
  	printf("Error: Unable to Capture Packets\n");
	return -1;
  }else{
  	printf("Received a packet with length %d\n",header.len);
	printf("Received at %s\n",ctime((const time_t*) &header.ts.tv_sec));
	printf("Enternet Header Length: %d\n", ETHER_HDR_LEN);
//---------------------------------------------------------------------------------------------------------------------------------------	
	eptr = (struct ether_header*) packet;
	if(ntohs(eptr->ether_type) == ETHERTYPE_IP){
		printf("Ethernet Type Hex: 0x%x; dec: %d is an IP Packet \n",ETHERTYPE_IP,ETHERTYPE_IP );	
	}else if(ntohs(eptr->ether_type) == ETHERTYPE_ARP){
		printf("Ethernet Type Hex: 0x%x; dec: %d is an ARP Packet \n",ETHERTYPE_ARP,ETHERTYPE_ARP );	
	}else{
 		printf("Ethernet Type Hex: 0x%x; dec: %d is not an  ARP  or IP Packet \n",ntohs(eptr->ether_type),ntohs(eptr->ether_type)); 	
	}
//---------------------------------------------------------------------------------------------------------------------------------------		

	hard_ptr= eptr->ether_dhost;

	i= ETHER_ADDR_LEN;
	printf("Destination Address: ");
	do {
		printf("%s%x",(i==ETHER_ADDR_LEN)? " ": ":", *hard_ptr++ );
		
	}while(--i>0);

	hard_ptr= eptr->ether_shost;
	printf("\n");
	i= ETHER_ADDR_LEN;
	printf("Source Address: ");
	do {
		printf("%s%x",(i==ETHER_ADDR_LEN)? " ": ":", *hard_ptr++ );
	}while(--i>0);

  } 
 }

return 0;
}