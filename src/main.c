
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

void enviarPacotesComAtrasos(float valueGSE, pcap_t *fp) {
    int delay = 0;  // Atraso inicial de 3ms
    int max_delay = 20;  // Atraso máximo de 20ms

    while (delay <= max_delay) {
        unsigned char buf[BUFFER_LENGTH] = {0};
        int len = 0;

        E1Q1SB1.S1.C1.TVTRa_1.Vol.instMag.f = valueGSE;
        len = E1Q1SB1.S1.C1.LN0.ItlPositions.send(buf, 1, delay);
        pcap_sendpacket(fp, buf, len);
        printf("Enviando pacotes com atraso de %d ms\n", delay);
        usleep(delay * 1000);  // Converte para microssegundos

        struct timeval current_time;
        gettimeofday(&current_time, NULL);

        // Converter os microssegundos em milissegundos
        long milliseconds = (current_time.tv_sec * 1000) + (current_time.tv_usec / 1000);

        printf("Hora atual em milissegundos: %ld ms\n", milliseconds);
        delay += 2;  // Incremento de 2ms a cada iteração
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
    fprintf(stdout, "%s\n", used_if->name);
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

    //pcap_freealldevs(alldevs);

	return fpl;
}

int main() {

    int len = 0;

    float valueGSE = (float)rand() / (float)RAND_MAX;
    initialise_iec61850();
    fp = initWinpcap();

    enviarPacotesComAtrasos(valueGSE, fp);


	gse_sv_packet_filter(buf, len);
	printf("GSE test: %s\n", D1Q1SB4.S1.C1.RSYNa_1.gse_inputs_ItlPositions.E1Q1SB1_C1_Positions.C1_TVTR_1_Vol_instMag.f == valueGSE ? "passed" : "failed");
	printf("Len: %d\n", len);

	fflush(stdout);

	// test database lookup
	unsigned char databaseValueResult = 0;
	Item *ln = getLN("E1Q1SB1", "C1", "TVTRa_1");
	if (ln != NULL) {
		Item *valueDatabaseRef = getItem(ln, 3, "Vol", "instMag", "f");
		if (valueDatabaseRef != NULL) {
			float *databaseValue = (float *) (valueDatabaseRef->data);

			if (*databaseValue == valueGSE) {
				databaseValueResult = TRUE;
			}
		}
		else {
			printf("Database lookup test: item null\n");
		}
	}
	else {
		printf("Database lookup test: LN null\n");
	}
	printf("Database lookup test: %s\n", databaseValueResult ? "passed" : "failed");
	fflush(stdout);

	pcap_close(fp);

	return 0;
}
