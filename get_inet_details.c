#include<stdio.h>
#include<stdlib.h>
#include<pcap.h> //To invoke the Libpcap Library and use its functions 
#include<errno.h> //For error numbers 
#include<sys/socket.h>
#include<netinet/in.h> // Used for Ipv6 or ipv4 Types 
#include<arpa/inet.h> // arpa is a package, which has basic things like telnet, ip, lookup etc 

int main(){
  char *device_name, *net_addr, *net_mask; // to store device name, ip, mask
  int return_code;
  char error[PCAP_ERRBUF_SIZE];
  
  bpf_u_int32 net_addr_int, net_mask_int ; // gives IP address as  unsigned 32 bit integer value 
  struct in_addr addr; // internet Address structure 

  //Asks Pcap to give us a vaild eth based device to sniff on it 
  
  device_name =pcap_lookupdev(error);  
  if(device_name==NULL){
  	printf("%s\n",error);
	return -1;  
  }else{
  	printf("Device: %s\n",device_name);
  }
 
  // With the device in the place aquire the Ip address and the subnet mask  
  return_code = pcap_lookupnet(device_name, &net_addr_int, &net_mask_int, error); //lookupnet is no more working this is for demo purpose only 
  if(return_code ==-1){
	printf("%s\n",error);
	return -1;  
  }
  
  //change address to Human readable form i.e Convert the 32 bit IP and Mask . 
  
  addr.s_addr = net_addr_int;
  net_addr = inet_ntoa(addr);
  
  if(net_addr == NULL) {
 	printf("inet_ntoa: Error Converting\n");
        return -1;
  }else{
  	printf("NET: %s\n",net_addr); 
  }



  addr.s_addr = net_mask_int;
  net_mask = inet_ntoa(addr);
  if(net_mask == NULL) {
 	printf("inet_ntoa: Error Converting\n");
        return -1;
  }else{
  	printf("Mask: %s\n",net_mask); 
  }

 return 0;
}