/*
This Program retrives all the interfaces from a machine using libcap library 

prerequisites
-------------

install libcap
sudo apt-get install libpcap-dev

While Complilation use -lpcap to say the compiler that you are goning to use pcal lib 

*/
#include<stdio.h>
#include<stdlib.h>
#include<pcap.h> //To invoke the Libpcap Library and use its functions 
#include<errno.h> //For error numbers 
#include<sys/socket.h>
#include<netinet/in.h> // Used for Ipv6 or ipv4 Types 
#include<arpa/inet.h> // arpa is a package, which has basic things like telnet, ip, lookup etc 

int main(int argc, char *argv[]){
  char error[PCAP_ERRBUF_SIZE];
  pcap_if_t *interfaces, *temp; // Pcap_if_t is a structure defined in pcap.h 
  int i=0; // for counting the number of interfaces 
  
  if(pcap_findalldevs(&interfaces, error)==-1){
   printf("Cannot Acquire the Devices :(" );
   return -1;
  }
  printf("The Available Interfaces are:\n");
  for(temp=interfaces; temp;temp=temp->next) // Similar to linked list nodes, consider interfaces as head and temp is pointed to head
  {
    printf("#%d: %s\n",++i,temp->name);
  }
  return 0;
}