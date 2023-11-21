
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
FILE *file;
int contador = 0;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	gse_sv_packet_filter((unsigned char *) pkt_data, header->len);
}
/// F
char* utc() {
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);

		struct tm tm;
		localtime_r(&ts.tv_sec, &tm);

		char formattedTime[20];
		strftime(formattedTime, sizeof(formattedTime), "%H:%M:%S", &tm);

		printf("Hora envio: %s.%09ld\n", formattedTime, ts.tv_nsec);
}
char* formatString(char* hora, int contador, int len, float valor) {
    // Aloca espaço para a string resultante
    char* result = (char*)malloc(256);  // Ajuste o tamanho conforme necessário

    // Obtém o tempo atual
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    struct tm* time_info = gmtime(&current_time.tv_sec);

    // Formata os valores na string
    sprintf(result, "%d-%02d-%02d %02d:%02d:%02d.%06ld,%f,%d,%d",
            1900 + time_info->tm_year, time_info->tm_mon + 1, time_info->tm_mday,
            time_info->tm_hour, time_info->tm_min, time_info->tm_sec,
            current_time.tv_usec, valor, contador, len);

    // Retorna a string resultante
    return result;
}

void enviarPacoteSV(float valueSV, pcap_t *fp) {
    unsigned char buf[BUFFER_LENGTH] = {0};

	// test Sampled Values
	E1Q1SB1.S1.C1.exampleRMXU_1.AmpLocPhsA.instMag.f = rand();

	printf("Enviando value SV: %f\n", valueSV);

	int i = 0;
	for (i = 0; i < E1Q1SB1.S1.C1.LN0.rmxuCB.noASDU; i++) {
		len = E1Q1SB1.S1.C1.LN0.rmxuCB.update(buf);
		if (len > 0) {
			contador++;
			char* hora = utc();
			printf("len value SV: %d\n", len);
			pcap_sendpacket(fp, buf, len);
			gse_sv_packet_filter(buf, len);

			printf("Valor: %f\n", D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[0].C1_RMXU_1_AmpLocPhsA.instMag.f);
			printf("SV test: %s\n", D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[15].C1_RMXU_1_AmpLocPhsA.instMag.f == valueSV ? "passed" : "failed");
			fflush(stdout);
			printf("Valor de i: %d \n",i);
			printf("\n");
			
			int inputValue = D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[15].C1_RMXU_1_AmpLocPhsA.instMag.f;
    		char* stringFormatada = formatString(hora, contador,len, inputValue);
		// Escreve cabeçalho (opcional)
			fprintf(file, "%s\n", stringFormatada);
		}

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

	file = fopen("enviaSV.csv", "a"); // Abre o arquivo para escrita (modo de adição)

	int max_delay = 300;
	int delay = 0;
	clock_t inicio = clock();	
    while (delay <= max_delay) {
    	enviarPacoteSV(valueSV, fp);
		usleep(208); // Espera por 208 nanossegundos
	    delay++; // Incrementa delay (ou use a lógica desejada para ajustar o valor de delay)
	}
    clock_t fim = clock();
    double tempoDecorrido = ((double)(fim - inicio)) / CLOCKS_PER_SEC;
    printf("O programa levou %.6f segundos para executar.\n", tempoDecorrido);

	fflush(stdout);
	pcap_close(fp);
	fclose(file);


	return 0;
}
