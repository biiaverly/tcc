
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include "iec61850.h"
#include "json/json.h"

#define BUFFER_LENGTH	2048

pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
unsigned char buf[BUFFER_LENGTH] = {0};
int len = 0;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	gse_sv_packet_filter((unsigned char *) pkt_data, header->len);
}


void enviarPacoteSV(float valueSV, pcap_t *fp) {
    unsigned char buf[BUFFER_LENGTH] = {0};

	// test Sampled Values
	E1Q1SB1.S1.C1.exampleRMXU_1.AmpLocPhsA.instMag.f = valueSV;
	E1Q1SB1.S1.C1.exampleRMXU_1.AmpLocPhsB.instMag.f = 2;

	printf("Enviando value SV: %f\n", valueSV);

	int i = 0;
	for (i = 0; i < E1Q1SB1.S1.C1.LN0.rmxuCB.noASDU; i++) {
		len = E1Q1SB1.S1.C1.LN0.rmxuCB.update(buf);
		printf("len value SV: %d\n", len);

		if (len > 0) {
			pcap_sendpacket(fp, buf, len);
			
			gse_sv_packet_filter(buf, len);

			printf("Valor: %f\n", D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[0].C1_RMXU_1_AmpLocPhsA.instMag.f);
			printf("Valor: %f\n", D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[1].C1_RMXU_1_AmpLocPhsA.instMag.f);

			printf("SV test: %s\n", D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[15].C1_RMXU_1_AmpLocPhsA.instMag.f == valueSV ? "passed" : "failed");
			fflush(stdout);
		}
		printf("%d",i);
	}

}

pcap_t *initWinpcap() {
	pcap_t *fpl;
    pcap_if_t *alldevs;
    pcap_if_t *used_if;


	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

    used_if = alldevs;
    fflush(stdout);

	if ((fpl = pcap_open_live(used_if->name,	// name of the device
							 65536,				// portion of the packet to capture. It doesn't matter in this case
							 1,					// promiscuous mode (nonzero means promiscuous)
							 1000,				// read timeout
							 errbuf				// error buffer
							 )) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", alldevs->name);
		exit(2);
	}

	return fpl;
}

int main() {

    int len = 0;
	float valueSV = (float) rand() / (float) RAND_MAX;
    initialise_iec61850();
    fp = initWinpcap();



    enviarPacoteSV(valueSV, fp);


	fflush(stdout);
	pcap_close(fp);


	return 0;
}
