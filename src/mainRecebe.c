#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include "iec61850.h"
#include "json/json.h"
struct timeval inicioProcessamento, fimProcessamento;
#define BUFFER_LENGTH	2048
struct timeval iniciorecebimentno, fimrecebimento,inicioEnvioPacotes,fimEnvioPacotes,inicioEnvioPacote,fimEnvioPacote;

pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
unsigned char buf[BUFFER_LENGTH] = {0};
int len = 0;


void utc() {
    struct timeval current_time;
    struct tm *time_info;

    // Obtém o tempo atual
    gettimeofday(&current_time, NULL);

    // Converte para UTC
    time_info = gmtime(&current_time.tv_sec);

    // Formata e imprime a hora em UTC com milissegundos
    printf("%d-%02d-%02d %02d:%02d:%02d.%03ld\n",
           1900 + time_info->tm_year, time_info->tm_mon + 1, time_info->tm_mday,
           time_info->tm_hour, time_info->tm_min, time_info->tm_sec,
           current_time.tv_usec / 1000);
}

static int contador = 0; // Declara um contador como estático para preservar seu valor entre chamadas
static int contadorSV = 0; // Declara um contador como estático para preservar seu valor entre chamadas

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
		gettimeofday(&iniciorecebimentno, NULL);
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);

		struct tm tm;
		localtime_r(&ts.tv_sec, &tm);

		char formattedTime[20];
		strftime(formattedTime, sizeof(formattedTime), "%H:%M:%S", &tm);

		printf("Hora recebimento: %s.%09ld\n", formattedTime, ts.tv_nsec);
	if (pkt_data[3] == 0x01) {
		contador++; // Incrementa o contador dentro do if

		printf("Pacote %d capturado: %d bytes\n",contador, header->len);


		
		gse_sv_packet_filter((unsigned char *) pkt_data, header->len);

		E1Q1SB1.S1.C1.TVTRa_1.Vol.instMag.f = D1Q1SB4.S1.C1.RSYNa_1.gse_inputs_ItlPositions.E1Q1SB1_C1_Positions.C1_TVTR_1_Vol_instMag.f;
		int length2 = E1Q1SB1.S1.C1.LN0.ItlPositions.send((unsigned char *) pkt_data, 1, 512);  // generate a goose packet, and store the bytes in "buffer"                   // set a value that appears in the dataset used by the "ItlPositions" GOOSE Control

		gse_sv_packet_filter((unsigned char *) pkt_data, length2);
		float inputValue = D1Q1SB4.S1.C1.RSYNa_1.gse_inputs_ItlPositions.E1Q1SB1_C1_Positions.C1_TVTR_1_Vol_instMag.f;
		printf("Valor %f\n",inputValue);

    }
	
	if (pkt_data[3] == 0x04) {
		contadorSV++; // Incrementa o contador dentro do if

		printf("Pacote SV %d capturado: %d bytes\n",contadorSV, header->len);


		
		gse_sv_packet_filter((unsigned char *) pkt_data, header->len);

		len = E1Q1SB1.S1.C1.LN0.rmxuCB.update(buf);
		printf("len value SV: %d\n", len);
		int length2 = E1Q1SB1.S1.C1.LN0.ItlPositions.send((unsigned char *) pkt_data, 1, 512);  // generate a goose packet, and store the bytes in "buffer"                   // set a value that appears in the dataset used by the "ItlPositions" GOOSE Control
		printf("Valor : %f\n", D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[15].C1_RMXU_1_AmpLocPhsA.instMag.f);
		gse_sv_packet_filter((unsigned char *) pkt_data, length2);
		float inputValue = D1Q1SB4.S1.C1.RSYNa_1.gse_inputs_ItlPositions.E1Q1SB1_C1_Positions.C1_TVTR_1_Vol_instMag.f;
		printf("Valor %f\n",inputValue);

    }	
		printf("\n");


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

    //pcap_freealldevs(alldevs);

	return fpl;
}

int main() {
	int len = 0;

	initialise_iec61850();
	fp = initWinpcap();

	printf("Inicio captura de pacote: ");
	pcap_loop(fp, 50, packet_handler,NULL);
	printf("\n");

	
	pcap_close(fp);


	return 0;
}
