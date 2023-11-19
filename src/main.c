
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include "iec61850.h"
#include "json/json.h"

#define BUFFER_LENGTH	2048
struct timeval inicioProcessamento, fimProcessamento,inicioEnvioPacotes,fimEnvioPacotes,inicioEnvioPacote,fimEnvioPacote;

pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
unsigned char buf[BUFFER_LENGTH] = {0};
int len = 0;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	gse_sv_packet_filter((unsigned char *) pkt_data, header->len);
}


void enviarPacotesComAtrasos(float valueGSE, pcap_t *fp) {

    gettimeofday(&inicioEnvioPacotes, NULL);

	int delay = 2;  
    int max_delay = 20; 
    int len = 0;
    unsigned char buf[BUFFER_LENGTH] = {0};

	printf("Enviando pacotes com atraso de %d ms\n", 0);

	/// Enviando o primeiro pacote apos um Evento (senf(buf,1,2))
    E1Q1SB1.S1.C1.TVTRa_1.Vol.instMag.f = valueGSE;

	struct timeval tv;
	struct tm *timeinfo;
	char buffer[80];
	char ms_buffer[18];

	gettimeofday(&tv, NULL);
	timeinfo = gmtime(&tv.tv_sec);
	len = E1Q1SB1.S1.C1.LN0.ItlPositions.send(buf, 1, 2);
	pcap_sendpacket(fp, buf, len);

	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);

	struct tm tm;
	localtime_r(&ts.tv_sec, &tm);

	char formattedTime[20];
	strftime(formattedTime, sizeof(formattedTime), "%H:%M:%S", &tm);

	printf("%s.%09ld\n", formattedTime, ts.tv_nsec);

    while (delay <= max_delay) {
		gettimeofday(&inicioEnvioPacote, NULL);

        usleep(delay * 1000);  // Converte para microssegundos
        printf("Enviando pacotes com atraso de %d ms\n", delay);
        pcap_sendpacket(fp, buf, len);

	/// Enviando os pacotes seguintes (senf(buf,0,2))


		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);

		struct tm tm;
		localtime_r(&ts.tv_sec, &tm);

		char formattedTime[20];
		strftime(formattedTime, sizeof(formattedTime), "%H:%M:%S", &tm);

		printf("Hora do envio: %s.%09ld\n", formattedTime, ts.tv_nsec);


		gettimeofday(&fimEnvioPacote, NULL);

		double tempoProcessamentoPacote = (double)(fimEnvioPacote.tv_sec - inicioEnvioPacote.tv_sec) + (double)(fimEnvioPacote.tv_usec - inicioEnvioPacote.tv_usec) / 1000000.0;
		double tempoEnvioPacote = (double)(fimEnvioPacote.tv_sec - inicioEnvioPacotes.tv_sec) + (double)(fimEnvioPacote.tv_usec - inicioEnvioPacotes.tv_usec) / 1000000.0;

		printf("Tempo processamento Pacote: %f segundos\n",tempoProcessamentoPacote);
		printf("Tempo envio Pacote: %f segundos\n", tempoEnvioPacote);
		printf("\n");

        delay += 2;  // Incremento de 2ms a cada iteração
    }
	gettimeofday(&fimEnvioPacotes, NULL);
	double tempoEnvioPacote = (double)(fimEnvioPacotes.tv_sec - inicioEnvioPacotes.tv_sec) + (double)(fimEnvioPacotes.tv_usec - inicioEnvioPacotes.tv_usec) / 1000000.0;
	printf("Tempo envio Pacotes: %f segundos\n", tempoEnvioPacote);
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
    float valueGSE = (float)rand() / (float)RAND_MAX;
    initialise_iec61850();
    fp = initWinpcap();



    enviarPacotesComAtrasos(valueGSE, fp);


	fflush(stdout);
	pcap_close(fp);


	return 0;
}
